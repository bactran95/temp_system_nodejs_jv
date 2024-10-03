# Airbnb javascript Style
### Use Const and Let
- Use `const` and `let` instead of `var`.
- Use `const` by default, unless a variable needs to be reassigned.

### Use Default Parameters
- Use default parameter syntax rather than short-circuiting. for example 
```
function foo(x = 1) {
  return x;
}
```

### Use Template Literals
- Use template literals instead of concatenation.
example:
```
const name = "John";
console.log(`Hello, ${name}!`);
```

### Use Arrow Functions
- Use arrow functions instead of function expressions.
for example:
```
const add = (a, b) => a + b;
```

### Use Async/Await
- Use async/await instead of raw Promises.

### Use Classes
- Use classes instead of prototypes.

### Use Modules
- Use modules (import/export) over a non-standard module system.

### Use Strict Equality
- Use `===` and `!==` instead of `==` and `!=`.

### Use Ternary Operators
- Use ternary operators for simple conditional statements.
for example:
```
const foo = (x > 0) ? "positive" : "negative";
```

### Use Short-Circuit Evaluation
- Use short-circuit evaluation for setting default values.
for example:
```
const foo = input || "default";
```

### Use Default Exports
- Use default exports for single exports.
for example:
```
export default function foo() { ... }
```

### Use Named Exports
- Use named exports for multiple exports.
for example:
```
export const = foo => () { ... }
```

### Use property value shorthand
- Use property value shorthand.
for example:
```
const x = 1;
const obj = {
  x,
};
```

### Group your shorthand properties at the beginning of your object declaration.
- It’s easier to tell which properties are using the shorthand.

```
const obj = {
  lukeSkywalker,
  anakinSkywalker,
  episodeOne: 1,
  twoJediWalkIntoACantina: 2,
  episodeThree: 3,
  mayTheFourth: 4,
};
```
