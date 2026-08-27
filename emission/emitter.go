package emission

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
)

const DefaultMaxListeners = 10

var ErrNoneFunction = errors.New("Kind of Value for listener is not Func.")

type RecoveryListener func(interface{}, interface{}, error)

type Emitter struct {
	*sync.Mutex
	events map[interface{}][]reflect.Value
	recoverer RecoveryListener
	maxListeners int
	onces map[interface{}][]reflect.Value
}

func (emitter *Emitter) AddListener(event, listener interface{}) *Emitter {
	emitter.Lock()
	defer emitter.Unlock()

	fn := reflect.ValueOf(listener)

	if reflect.Func != fn.Kind() {
		if nil == emitter.recoverer {
			panic(ErrNoneFunction)
		} else {
			emitter.recoverer(event, listener, ErrNoneFunction)
		}
	}

	if emitter.maxListeners != -1 && emitter.maxListeners < len(emitter.events[event])+1 {
		fmt.Fprintf(os.Stdout, "Warning: event `%v` has exceeded the maximum "+
			"number of listeners of %d.\n", event, emitter.maxListeners)
	}

	emitter.events[event] = append(emitter.events[event], fn)

	return emitter
}

func (emitter *Emitter) On(event, listener interface{}) *Emitter {
	return emitter.AddListener(event, listener)
}

func (emitter *Emitter) RemoveListener(event, listener interface{}) *Emitter {
	emitter.Lock()
	defer emitter.Unlock()

	fn := reflect.ValueOf(listener)

	if reflect.Func != fn.Kind() {
		if nil == emitter.recoverer {
			panic(ErrNoneFunction)
		} else {
			emitter.recoverer(event, listener, ErrNoneFunction)
		}
	}

	if events, ok := emitter.events[event]; ok {
		newEvents := []reflect.Value{}

		for _, listener := range events {
			if fn.Pointer() != listener.Pointer() {
				newEvents = append(newEvents, listener)
			}
		}

		emitter.events[event] = newEvents
	}

	if events, ok := emitter.onces[event]; ok {
		newEvents := []reflect.Value{}

		for _, listener := range events {
			if fn.Pointer() != listener.Pointer() {
				newEvents = append(newEvents, listener)
			}
		}

		emitter.onces[event] = newEvents
	}

	return emitter
}

func (emitter *Emitter) Off(event, listener interface{}) *Emitter {
	return emitter.RemoveListener(event, listener)
}

func (emitter *Emitter) Once(event, listener interface{}) *Emitter {
	emitter.Lock()
	defer emitter.Unlock()

	fn := reflect.ValueOf(listener)

	if reflect.Func != fn.Kind() {
		if nil == emitter.recoverer {
			panic(ErrNoneFunction)
		} else {
			emitter.recoverer(event, listener, ErrNoneFunction)
		}
	}

	if emitter.maxListeners != -1 && emitter.maxListeners < len(emitter.onces[event])+1 {
		fmt.Fprintf(os.Stdout, "Warning: event `%v` has exceeded the maximum "+
			"number of listeners of %d.\n", event, emitter.maxListeners)
	}

	emitter.onces[event] = append(emitter.onces[event], fn)
	return emitter
}

func (emitter *Emitter) Emit(event interface{}, arguments ...interface{}) *Emitter {
	var (
		listeners []reflect.Value
		ok        bool
	)

	emitter.Lock()

	if listeners, ok = emitter.events[event]; !ok {

		emitter.Unlock()
		goto ONCES
	}

	emitter.Unlock()
	emitter.callListeners(listeners, event, arguments...)

ONCES:

	emitter.Lock()
	if listeners, ok = emitter.onces[event]; !ok {
		emitter.Unlock()
		return emitter
	}
	emitter.Unlock()
	emitter.callListeners(listeners, event, arguments...)
	emitter.onces[event] = emitter.onces[event][len(listeners):]
	return emitter
}

func (emitter *Emitter) callListeners(listeners []reflect.Value, event interface{}, arguments ...interface{}) {
	var wg sync.WaitGroup

	wg.Add(len(listeners))

	for _, fn := range listeners {
		go func(fn reflect.Value) {
			defer wg.Done()

			if nil != emitter.recoverer {
				defer func() {
					if r := recover(); nil != r {
						err := fmt.Errorf("%v", r)
						emitter.recoverer(event, fn.Interface(), err)
					}
				}()
			}

			var values []reflect.Value

			for i := 0; i < len(arguments); i++ {
				if arguments[i] == nil {
					values = append(values, reflect.New(fn.Type().In(i)).Elem())
				} else {
					values = append(values, reflect.ValueOf(arguments[i]))
				}
			}

			fn.Call(values)
		}(fn)
	}

	wg.Wait()
}

func (emitter *Emitter) RecoverWith(listener RecoveryListener) *Emitter {
	emitter.recoverer = listener
	return emitter
}

func (emitter *Emitter) SetMaxListeners(max int) *Emitter {
	emitter.Lock()
	defer emitter.Unlock()

	emitter.maxListeners = max
	return emitter
}

func (emitter *Emitter) GetListenerCount(event interface{}) (count int) {
	emitter.Lock()
	if listeners, ok := emitter.events[event]; ok {
		count = len(listeners)
	}
	emitter.Unlock()
	return
}

func NewEmitter() (emitter *Emitter) {
	emitter = new(Emitter)
	emitter.Mutex = new(sync.Mutex)
	emitter.events = make(map[interface{}][]reflect.Value)
	emitter.maxListeners = DefaultMaxListeners
	emitter.onces = make(map[interface{}][]reflect.Value)
	return
}
