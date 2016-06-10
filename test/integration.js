import expect from "expect.js";
import {parseScript, parseModule} from "shift-parser";
import codegen from "shift-codegen";
import isValid from "shift-validator";

import {testRepeatedly} from "./helpers";
import {fuzzScript, fuzzModule, fuzzWhileStatement} from "../";


suite("integration", () => {
  testRepeatedly("script round-trips through our codegen and parser", () => {
    let program;
    do { program = fuzzScript(); } while(!isValid(program));
    let roundTripped;
    try {
      roundTripped = parseScript(codegen(program));
      expect(roundTripped).to.be.eql(parseScript(codegen(roundTripped)));
    } catch(e) {
      if (e.description && (e.description.match('Duplicate binding'))) return;
      // todo remove catch entirely
      console.log(codegen(program))
      console.log(e)
      throw e;
    }
  });

  testRepeatedly("module round-trips through our codegen and parser", () => {
    let program;
    do { program = fuzzModule(); } while(!isValid(program));
    let roundTripped;
    try {
      roundTripped = parseModule(codegen(program));
      expect(roundTripped).to.be.eql(parseModule(codegen(roundTripped)));
    } catch(e) {
      if (e.description && (e.description.match('Duplicate binding') || e.description.match('Duplicate export') || e.description.match('is not declared'))) return;
      // todo remove catch entirely
      console.log(codegen(program))
      console.log(e)
      throw e;
    }
  });
});
