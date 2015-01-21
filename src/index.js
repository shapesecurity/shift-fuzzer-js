import * as objectAssign from "object-assign";
import * as Shift from "shift-ast";

const FUZZER_STATE_DEFAULT_OPTIONS = {
  rng: Math.Random,
  maxDepth: 7
}

export class FuzzerState {
  constructor(options = {}) {
    this.options = {};
    Object.assign(this.options, FUZZER_STATE_DEFAULT_OPTIONS);
    Object.assign(this.options, options);

    this.depth = 0;
  }

  clone() {
    let st = new FuzzerState(this.options);
    st.depth = this.depth;
    return st;
  }

  goDeeper() {
    let st = this.clone();
    ++st.depth;
    return st;
  }

  tooDeep() {
    return this.depth >= this.options.maxDepth;
  }
}




function many(fuzzer) {
  return function(fuzzerState) {
    
  };
}





export default function(fuzzerState = new FuzzerState) {
  return fuzzProgram(fuzzerState);
}

export function fuzzProgram(fuzzerState) {
  return fuzzScript(fuzzerState);
}

export function fuzzScript(fuzzerState) {
  let f = fuzzerState.goDeeper();
  return f.tooDeep()
    ? new Shift.Script(new Shift.FunctionBody([], []))
    : new Shift.Script(fuzzFunctionBody(f));
}

export function fuzzFunctionBody(fuzzerState) {
  let f = fuzzerState.goDeeper();
  return f.tooDeep()
    ? new Shift.FunctionBody([], [])
    : new Shift.FunctionBody(many(fuzzDirective)(f), many(fuzzStatement)(f));
}

