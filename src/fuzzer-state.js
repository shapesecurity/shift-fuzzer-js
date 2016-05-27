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

import Random from "./random";

export default class FuzzerState {
  constructor({maxDepth = 7, rng = Math.random} = {}) {
    this.maxDepth = maxDepth;
    this.rng = new Random(rng);

    this.depth = 0;
    this.inIteration = false; // allows continue and unlabelled break
    this.inSwitch = false; // allows unlabelled break // todo consider collapsing into one allowBreak, one allowContinue
    this.strict = false;
    this.allowReturn = false;
    this.allowNewTarget = false;
    this.constructorMayContainSuperCall = false; // set only in classes which inherit, and not passed to children
    this.allowSuperCall = false; // todo generate constructor methods more often
    this.allowSuperProp = false; // implied by allowSuperCall
    this.allowMissingElse = true;
    this.inForInOfHead = false; // in ForIn/Of heads, variable declarators must be of length 1 and lack initializers
    this.requireDeclaratorInitializers = false; // for const variable declarations
    this.allowYieldIdentifier = true;
    this.allowYieldExpr = false; // mutually exclusive with the above, but both can be false, e.g. in formal parameters of or within a generator
    this.allowProperDeclarations = true; // if false, prohibits all declarations except `var` and non-generator `function`. applies to labelled statements and bodies of ifs, loops, and with. 
    this.allowFunctionDeclarations = true; // prohibited exclusively in loop and with bodies. is implied by allowProperDeclarations.

    this.labels = []; // would use a set, but we need immutibility.
    this.loopLabels = [];
  }

  clone() {
    let st = Object.create(FuzzerState.prototype);
    st.maxDepth = this.maxDepth;
    st.rng = this.rng;
    st.depth = this.depth;
    st.inIteration = this.inIteration;
    st.inSwitch = this.inSwitch;
    st.strict = this.strict;
    st.allowReturn = this.allowReturn;
    st.allowNewTarget = this.allowNewTarget;
    st.constructorMayContainSuperCall = this.constructorMayContainSuperCall;
    st.allowSuperCall = this.allowSuperCall;
    st.allowSuperProp = this.allowSuperProp;
    st.allowMissingElse = this.allowMissingElse;
    st.inForInOfHead = this.inForInOfHead;
    st.requireDeclaratorInitializers = this.requireDeclaratorInitializers;
    st.allowYieldIdentifier = this.allowYieldIdentifier;
    st.allowYieldExpr = this.allowYieldExpr;
    st.allowProperDeclarations = this.allowProperDeclarations;
    st.allowFunctionDeclarations = this.allowFunctionDeclarations;
    st.labels = this.labels;
    st.loopLabels = this.loopLabels;
    return st;
  }

  goDeeper() {
    let st = this.clone();
    ++st.depth;
    return st;
  }

  tooDeep() {
    return this.depth >= this.maxDepth;
  }

  allowBreak() {
    return this.inIteration || this.inSwitch || this.labels.length !== 0;
  }

  enableMissingElse() {
    let st = this.clone();
    st.allowMissingElse = true;
    return st;
  }

  disableMissingElse() {
    let st = this.clone();
    st.allowMissingElse = false;
    return st;
  }

  enableDeclarations() {
    let st = this.clone();
    st.allowProperDeclarations = st.allowFunctionDeclarations = true;
    return st;
  }

  disableYieldExpr() {
    let st = this.clone();
    st.allowYieldExpr = false;
    return st;
  }

  enterFunction({isGenerator = false, isArrow = false, isMethod = false, isStrict = false} = {}) {
    let st = this.clone();
    if (st.allowMissingElse) throw 'missingelse'; // todo remove this assertion
    if (st.inForInOfHead) throw 'forinof';
    if (st.requireDeclaratorInitializers) throw 'declinit';

    st.inIteration = false;
    st.inSwitch = false;
    if (isStrict) { // todo we'll need to generate directives before anything else. also, set this in classes and modules.
      st.strict = true;
    }
    st.allowReturn = true;
    if (isArrow) {
      st.allowYieldExpr = false;
    } else {
      st.allowNewTarget = true;
      if (isGenerator) {
        st.allowYieldIdentifier = false;
        st.allowYieldExpr = true;
      } else {
        st.allowYieldIdentifier = true;
        st.allowYieldExpr = false;
      }
      if (!isMethod) {
        st.allowSuperCall = false;
        st.allowSuperProp = false;
      }
    }
    st.allowProperDeclarations = true;
    st.allowFunctionDeclarations = true;

    st.labels = [];
    st.loopLabels = [];
    return st;
  }
}

