const expect = require("expect.js");
const {parseScript, parseModule} = require("shift-parser");
const codegen = require("shift-codegen").default;
const {isValid, Validator} = require("shift-validator");

const {testRepeatedly} = require("./helpers");
const {fuzzScript, fuzzModule, fuzzLiteralRegExpExpression} = require("../");


suite("integration", () => {
  testRepeatedly("script round-trips through our codegen and parser", () => {
    let program = fuzzScript();
    let roundTripped;
    try {
      roundTripped = parseScript(codegen(program));
      expect(roundTripped).to.be.eql(parseScript(codegen(roundTripped)));
      expect(isValid(program)).to.be.ok();
    } catch(e) {
      if (e.description && (e.description.match('Duplicate binding'))) return;
      // todo remove catch entirely
      console.log(codegen(program));
      console.log(Validator.validate(program));
      console.log(e);
      throw e;
    }
  });

  const flagsFromRegexp = (expression) => {
    return [
      expression.global ? 'g' : '',
      expression.ignoreCase ? 'i' : '',
      expression.multiline ? 'm' : '',
      expression.sticky ? 'y' : '',
      expression.unicode ? 'u' : ''
    ].join('');
  }

  // covered in other tests, but more is better
  testRepeatedly("fuzzLiteralRegExpExpression round trips through our codegen and parser", () => {
    let expression = fuzzLiteralRegExpExpression();
    let flags = flagsFromRegexp(expression);
    let roundTripped;
    try{
      roundTripped = parseScript(codegen(expression)).statements[0].expression;
    } catch (e) {
      throw new Error(`failed to parse regexp: expected: /${expression.pattern}/${flags} got error: ${e}`);
    }
    try {
      expect(roundTripped).to.be.eql(expression);
    } catch (e) {
      let otherFlags = flagsFromRegexp(roundTripped);
      throw new Error(`regexp not equal in parse and codegen: expected: /${expression.pattern}/${flags} got: /${roundTripped.pattern}/${otherFlags}`);
    }
  });

  testRepeatedly("module round-trips through our codegen and parser", () => {
    let program = fuzzModule();
    let roundTripped;
    try {
      roundTripped = parseModule(codegen(program));
      expect(roundTripped).to.be.eql(parseModule(codegen(roundTripped)));
      expect(isValid(program)).to.be.ok();
    } catch(e) {
      if (e.description && (e.description.match('Duplicate binding') || e.description.match('Duplicate export') || e.description.match('is not declared'))) return;
      // todo remove catch entirely
      console.log(codegen(program));
      console.log(Validator.validate(program));
      console.log(e);
      throw e;
    }
  });
});
