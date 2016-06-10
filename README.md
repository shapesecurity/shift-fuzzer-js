Shift Fuzzer
============


## About

This module provides a fuzzer for a [Shift format](https://shift-ast.org/) AST.


## Status

[Stable](http://nodejs.org/api/documentation.html#documentation_stability_index).


## Installation

```sh
npm install shift-fuzzer
```


## Usage

```js
import fuzzProgram, {FuzzerState, fuzzFunctionDeclaration} from "shift-fuzzer";
import render from "shift-codegen";

// generate random program
let randomProgramAst = fuzzProgram();
let randomProgram = render(randomProgramAst);
console.log(randomProgram);

// generate random FunctionDeclaration
let randomFunctionAst = fuzzFunctionDeclaration(new FuzzerState({maxDepth: 7}));
let randomFunction = render(randomFunctionAst);
console.log(randomFunction);

// generate random program from a seed
const RNG_SEED = 0xBADBE1BE1;
let prng =
  (function(state){
    return function nextDouble() {
      // implementation left as an exercise for the reader
    };
  }(RNG_SEED));
let seededRandomProgramAst = fuzzProgram(new FuzzerState({rng: prng, maxDepth: 7}));
let seededRandomProgram = render(seededRandomProgramAst);
console.log(seededRandomProgram);
```


## Contributing

* Open a Github issue with a description of your desired change. If one exists already, leave a message stating that you are working on it with the date you expect it to be complete.
* Fork this repo, and clone the forked repo.
* Install dependencies with `npm install`.
* Build and test in your environment with `npm run build && npm test`.
* Create a feature branch. Make your changes. Add tests.
* Build and test in your environment with `npm run build && npm test`.
* Make a commit that includes the text "fixes #*XX*" where *XX* is the Github issue.
* Open a Pull Request on Github.


## License

    Copyright 2014 Shape Security, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
