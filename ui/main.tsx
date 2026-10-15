import { render } from 'preact';
import { App } from './app';

// Object.prototype is locked against prototype pollution: nothing can be added to it, and none of its
// properties can be changed. Preact assigns `constructor` on plain objects when it copies vnodes, which a
// read-only `constructor` here would refuse (so Tauri's freezePrototype stops Preact's first re-render):
// it becomes an accessor that reads as before and gives an object assigned to it a property of its own.
for (const key of Reflect.ownKeys(Object.prototype)) {
  const d = Object.getOwnPropertyDescriptor(Object.prototype, key)!;
  if (key === 'constructor') {
    Object.defineProperty(Object.prototype, key, {
      get: () => Object,
      set(this: object, value: unknown) {
        Object.defineProperty(this, 'constructor', { value, writable: true, enumerable: true, configurable: true });
      },
      enumerable: false,
      configurable: false,
    });
  } else Object.defineProperty(Object.prototype, key, 'value' in d ? { writable: false, configurable: false } : { configurable: false });
}
Object.preventExtensions(Object.prototype);

render(<App />, document.getElementById('app')!);
