/**
 * Copyright 2014 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const FuzzerState = require("./fuzzer-state");

const MANY_BOUND = 5;

function manyN(bound) {
  return (fuzzer) =>
    guardDepth(
      () => [],
      (fuzzerState = new FuzzerState) => {
        let count = fuzzerState.rng.nextInt(bound + 1);
        let result = [];
        while(count-- > 0)
          result.push(fuzzer(fuzzerState));
        return result;
      }
    );
}

const many = manyN(MANY_BOUND);

function many1(fuzzer) {
  return (fuzzerState = new FuzzerState) => {
    let result = many(fuzzer)(fuzzerState);
    if (result.length === 0)
      result.push(fuzzer(fuzzerState));
    return result;
  };
}

function either(fuzzerA, fuzzerB) {
  return (fuzzerState = new FuzzerState) =>
    (fuzzerState.rng.nextBoolean() ? fuzzerA : fuzzerB)(fuzzerState);
}

function choose(...fuzzers) {
  switch(fuzzers.length) {
    case 0:
      throw new Error("choose must be given at least one fuzzer");
    case 1:
      return fuzzers[0];
    case 2:
      return either(fuzzers[0], fuzzers[1]);
    default:
      return (fuzzerState = new FuzzerState) =>
        fuzzers[fuzzerState.rng.nextInt(fuzzers.length)](fuzzerState);
  }
}

function oneOf(...values) {
  return (fuzzerState) =>
    values[fuzzerState.rng.nextInt(values.length)];
}

function opt(fuzzer) {
  return guardDepth(
    () => null,
    (fuzzerState = new FuzzerState) =>
      fuzzerState.rng.nextBoolean() ? null : fuzzer(fuzzerState)
  );
}

function ap(ctor, propFuzzers, fuzzerState = new FuzzerState) {
  let f = fuzzerState.goDeeper();
  let props = Object.create(null);
  for (let prop in propFuzzers) {
    if (!propFuzzers.hasOwnProperty(prop)) continue;
    props[prop] = propFuzzers[prop](f);
  }
  return new ctor(props);
}

function guardDepth(fuzzerA, fuzzerB) {
  return (fuzzerState = new FuzzerState) =>
    fuzzerState.tooDeep() ? fuzzerA(fuzzerState) : fuzzerB(fuzzerState);
}

module.exports = {
  MANY_BOUND,
  manyN,
  many,
  many1,
  either,
  choose,
  oneOf,
  opt,
  ap,
  guardDepth
};
