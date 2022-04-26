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

const Random = require("./random");

class FuzzerState {
  constructor({maxDepth = 7, rng = Math.random} = {}) {
    this.maxDepth = maxDepth;
    this.rng = new Random(rng);

    this.depth = 0;
    this.inLoop = false; // allows continue and unlabelled break
    this.inSwitch = false; // allows unlabelled break // todo consider collapsing into one allowBreak, one allowContinue
    this.strict = false;
    this.allowReturn = false;
    this.allowNewTarget = false;
    this.allowSuperCall = false; // todo generate constructor methods more often
    this.allowSuperProp = false; // implied by allowSuperCall
    this.allowMissingElse = true;
    this.declKind = null; // const requires initializer; const and let prohibit bindings named let.
    this.allowYieldIdentifier = true;
    this.allowYieldExpr = false; // mutually exclusive with the above, but both can be false, e.g. in formal parameters of or within a generator
    this.allowAwaitIdentifier = true;
    this.allowAwaitExpr = false; // mutually exclusive with the above, but both can be false, e.g. in formal parameters
    this.isModule = false;

    this.labels = []; // would use a set, but we need immutibility.
    this.loopLabels = []; // is a subset of labels
  }

  clone() {
    let st = Object.create(FuzzerState.prototype);
    st.maxDepth = this.maxDepth;
    st.rng = this.rng;
    st.depth = this.depth;
    st.inLoop = this.inLoop;
    st.inSwitch = this.inSwitch;
    st.strict = this.strict;
    st.allowReturn = this.allowReturn;
    st.allowNewTarget = this.allowNewTarget;
    st.allowSuperCall = this.allowSuperCall;
    st.allowSuperProp = this.allowSuperProp;
    st.allowMissingElse = this.allowMissingElse;
    st.declKind = this.declKind;
    st.allowYieldIdentifier = this.allowYieldIdentifier;
    st.allowYieldExpr = this.allowYieldExpr;
    st.allowAwaitIdentifier = this.allowAwaitIdentifier;
    st.allowAwaitExpr = this.allowAwaitExpr;
    st.isModule = this.isModule;
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
    return this.inLoop || this.inSwitch || this.labels.length !== 0;
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

  disableYieldExpr() {
    let st = this.clone();
    st.allowYieldExpr = false;
    return st;
  }

  disableAwaitExpr() {
    let st = this.clone();
    st.allowAwaitExpr = false;
    return st;
  }

  enterFunction({isGenerator = false, isAsync = false, isArrow = false, isMethod = false, hasStrictDirective = false} = {}) {
    let st = this.clone();
    if (st.declKind !== null) throw 'declKind'; // todo remove this

    st.inLoop = false;
    st.inSwitch = false;
    if (hasStrictDirective) {
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
    if (isAsync) {
      st.allowAwaitExpr = true;
      st.allowAwaitIdentifier = false;
    } else {
      st.allowAwaitExpr = false;
      st.allowAwaitIdentifier = !st.isModule;
    }
    st.allowMissingElse = true;

    st.labels = [];
    st.loopLabels = [];

    return st;
  }

  enterLoop() {
    let st = this.clone();
    st.inLoop = true;
    return st;
  }

  enterSwitch() {
    let st = this.clone();
    st.inSwitch = true;
    return st;
  }
}

module.exports = FuzzerState;
