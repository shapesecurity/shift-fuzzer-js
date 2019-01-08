/**
 * Copyright 2016 Shape Security, Inc.
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

import * as Shift from "shift-ast/checked";

import FuzzerState from "./fuzzer-state";
export { FuzzerState };
import { ap, choose, guardDepth, many, many1, manyN, oneOf, opt, MANY_BOUND } from "./combinators";
import fuzzRegExpPattern, { RegExpBugAvoidanceConfiguration } from "./regexp";
import Random from "./random";


const RESERVED =  [ // todo import this
  // keywords
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
  'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
  'for', 'function', 'if', 'import', 'in', 'instanceof', 'new', 'return',
  'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void', 'while',
  'with',
  // null, booleans
  'null', 'true', 'false',
  // future reserved word
  'enum',
];

const STRICT_FORBIDDEN = [
  'implements', 'package', 'protected', 'interface', 'private', 'public',
  'static'
];

const ALL_KNOWN_WORDS = RESERVED.concat(STRICT_FORBIDDEN).concat(['let', 'yield', 'await', 'eval', 'arguments', 'constructor', 'prototype']);

// special cases: 'let', 'yield', 'await', 'eval', 'arguments'


function identifierStart(fuzzerState) { // todo. see also https://gist.github.com/mathiasbynens/6334847#file-javascript-identifier-regex-js-L65-L105
  return String.fromCharCode(97 + fuzzerState.rng.nextInt(25));
}

const identifierPart = identifierStart; // todo
const MAX_IDENT_LENGTH = 15;

const genIdentifierString = f => identifierStart(f) + manyN(MAX_IDENT_LENGTH)(identifierPart)(f).join("");

const fuzzVariableName = (f, isBinding) => {
  let interestingNames = [];
  let forbiddenNames = [...RESERVED];
  if (f.strict) {
    forbiddenNames.push(...STRICT_FORBIDDEN, 'let', 'yield');
  } else {
    interestingNames.push(...STRICT_FORBIDDEN);
    (f.declKind === 'let' || f.declKind === 'const' ? forbiddenNames : interestingNames).push('let');
    (!f.allowYieldIdentifier ? forbiddenNames : interestingNames).push('yield');
  }
  (f.strict && isBinding ? forbiddenNames : interestingNames).push('eval', 'arguments');
  (!f.allowAwaitIdenifier ? forbiddenNames : interestingNames).push('await'); // this has the odd effect that strict-mode scripts have lots of variables named await.

  return fuzzIdentifier(f, interestingNames, forbiddenNames);
}

const fuzzLabel = f => { // todo consider collapsing into fuzzVariableName(f, false);
  let interestingNames = ['eval', 'arguments'];
  let forbiddenNames = [...RESERVED, ...f.labels];
  if (f.strict) {
    forbiddenNames.push(...STRICT_FORBIDDEN, 'let', 'yield');
  } else {
    interestingNames.push(...STRICT_FORBIDDEN, 'let');
    (!f.allowYieldIdentifier ? forbiddenNames : interestingNames).push('yield');
  }
  (!f.allowAwaitIdenifier ? forbiddenNames : interestingNames).push('await');

  f.labels.forEach(l => {
    let ind = interestingNames.indexOf(l);
    if (ind !== -1) {
      interestingNames.splice(ind, 1);
    }
  });

  return fuzzIdentifier(f, interestingNames, forbiddenNames);
}

export const fuzzIdentifier = (f = new FuzzerState, interestingNames = [], forbiddenNames = RESERVED) => {
  if (interestingNames.length > 0 && f.rng.nextBoolean()) {
    return oneOf(...interestingNames)(f);
  }

  while (true) {
    let possibleIdentifier = genIdentifierString(f);
    if (forbiddenNames.indexOf(possibleIdentifier) < 0) return possibleIdentifier;
  }
}

const fuzzIdentifierName = choose(genIdentifierString, oneOf(...ALL_KNOWN_WORDS));

const fuzzHexDigit = oneOf(...'0123456789abcdefABCDEF');

const fuzzString = f => f.rng.nextString();

const toRawValue = (f, str) => {
  // handle illegal escape sequences: 8, 9, trailing backslash, u, x, octals (in strict mode)
  let orig;
  do {
    orig = str;
    str = str.replace(/((^|[^\\])(\\\\)*\\)(8|9|u|x|$)/g, `$1\\$4`);
    // str = str.replace(/((^|[^\\])(\\\\)*\\)u/g, `$1u${f.rng.nextBoolean() ?
    //   `${fuzzHexDigit(f)}${fuzzHexDigit(f)}${fuzzHexDigit(f)}${fuzzHexDigit(f)}` :
    //   `{${fuzzHexDigit(f)}${manyN(4)(fuzzHexDigit)(f).join('')}}`
    // }`);
    // str = str.replace(/((^|[^\\])(\\\\)*\\)x/g, `$1x${fuzzHexDigit(f)}${fuzzHexDigit(f)}`); // todo consider inserting escape sequences like \u{XXXXX} etc into strings. This technique works, but not in combination with our hack for dealing with the \u\u case.
    if (f.strict) {
      str = str.replace(/((^|[^\\])(\\\\)*\\)0([0-7])/g, `$1\\0$4`);
      str = str.replace(/((^|[^\\])(\\\\)*\\)([1-7])/g, `$1\\$4`);
    }
  } while(str !== orig); // loop is to handle e.g. \8\8, because javascript lacks lookbehind and faking it is painful.
  return str;
}

export const fuzzArrayAssignmentTarget = f =>
  ap(Shift.ArrayAssignmentTarget, {"elements": many(opt(choose(fuzzAssignmentTargetWithDefault, fuzzAssignmentTarget))), "rest": opt(fuzzAssignmentTarget)}, f);

export const fuzzArrayBinding = f =>
  ap(Shift.ArrayBinding, {"elements": many(opt(choose(fuzzBindingWithDefault, fuzzBinding))), "rest": opt(fuzzBinding)}, f);

export const fuzzArrayExpression = f =>
  ap(Shift.ArrayExpression, {"elements": many(opt(choose(fuzzExpression, fuzzSpreadElement)))}, f);

export const fuzzArrowExpression = (f = new FuzzerState) => {
  let isConsise = f.rng.nextBoolean();
  let params, body;
  if (!isConsise) {
    let {directives, hasStrictDirective} = fuzzDirectives(f);
    f = f.enterFunction({isArrow: true, hasStrictDirective});
    params = fuzzFormalParameters(f, {hasStrictDirective});
    body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  } else {
    f = f.enterFunction({isArrow: true});
    params = fuzzFormalParameters(f);
    body = fuzzExpression(f);
  }
  return new Shift.ArrowExpression({params, body});
}

export const fuzzAssignmentExpression = f =>
  ap(Shift.AssignmentExpression, {"binding": fuzzAssignmentTarget, "expression": fuzzExpression}, f);

export const fuzzAssignmentTargetIdentifier = f =>
  ap(Shift.AssignmentTargetIdentifier, {"name": f => fuzzVariableName(f, true)}, f);

export const fuzzAssignmentTargetPropertyIdentifier = f =>
  ap(Shift.AssignmentTargetPropertyIdentifier, {"binding": fuzzAssignmentTargetIdentifier, "init": opt(fuzzExpression)}, f);

export const fuzzAssignmentTargetPropertyProperty = f =>
  ap(Shift.AssignmentTargetPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzAssignmentTargetWithDefault, fuzzAssignmentTarget)}, f);

export const fuzzAssignmentTargetWithDefault = f =>
  ap(Shift.AssignmentTargetWithDefault, {"binding": fuzzAssignmentTarget, "init": fuzzExpression}, f);

export const fuzzBinaryExpression = f =>
  ap(Shift.BinaryExpression, {"left": fuzzExpression, "operator": oneOf("==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof", "<<", ">>", ">>>", "+", "-", "*", "/", "%", "**", ",", "||", "&&", "|", "^", "&"), "right": fuzzExpression}, f);

export const fuzzBindingIdentifier = f =>
  ap(Shift.BindingIdentifier, {"name": f => fuzzVariableName(f, true)}, f);

export const fuzzBindingPropertyIdentifier = f =>
  ap(Shift.BindingPropertyIdentifier, {"binding": fuzzBindingIdentifier, "init": opt(fuzzExpression)}, f);

export const fuzzBindingPropertyProperty = f =>
  ap(Shift.BindingPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzBindingWithDefault, fuzzBinding)}, f);

export const fuzzBindingWithDefault = f =>
  ap(Shift.BindingWithDefault, {"binding": fuzzBinding, "init": fuzzExpression}, f);

export const fuzzBlock = f =>
  ap(Shift.Block, {"statements": many(fuzzStatement)}, f);

export const fuzzBlockStatement = f =>
  ap(Shift.BlockStatement, {"block": fuzzBlock}, f);

export const fuzzBreakStatement = f =>
  ap(Shift.BreakStatement, {"label": f => f.labels.length > 0 && (!(f.inLoop || f.inSwitch) || f.rng.nextBoolean()) ? oneOf(...f.labels)(f) : null}, f);

export const fuzzCallExpression = f =>
  ap(Shift.CallExpression, {"callee": fuzzExpressionSuperCall, "arguments": many(choose(fuzzExpression, fuzzSpreadElement))}, f);

export const fuzzCatchClause = f =>
  ap(Shift.CatchClause, {"binding": fuzzBinding, "body": fuzzBlock}, f);

export const fuzzClassDeclaration = (f = new FuzzerState) => {
  f = f.goDeeper();
  f.inLoop = f.inSwitch = false;
  f.strict = true;
  let name = fuzzBindingIdentifier(f);
  let _super = opt(fuzzExpression)(f);
  let elements = fuzzClassElements(f, {allowConstructor: _super !== null});
  return new Shift.ClassDeclaration({name, "super": _super, elements});
}

export const fuzzClassElement = (f = new FuzzerState, {allowConstructor = true, constructorMayContainSuperCall = false} = {}) => {
  f = f.goDeeper();
  let isStatic = f.rng.nextBoolean();
  let method = choose(f => fuzzGetter(f, {isStatic, inClass: true}), f => fuzzMethod(f, {isStatic, inClass: true, allowConstructor, constructorMayContainSuperCall}), f => fuzzSetter(f, {isStatic, inClass: true}))(f);
  return new Shift.ClassElement({isStatic, method});
}

export const fuzzClassExpression = (f = new FuzzerState) => {
  f = f.goDeeper();
  f.inLoop = f.inSwitch = false;
  f.strict = true;
  let name = opt(fuzzBindingIdentifier)(f);
  let _super = opt(fuzzExpression)(f);
  let elements = fuzzClassElements(f, {allowConstructor: _super !== null});
  return new Shift.ClassExpression({name, "super": _super, elements});
}

export const fuzzCompoundAssignmentExpression = f =>
  ap(Shift.CompoundAssignmentExpression, {"binding": choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget)), "operator": oneOf("+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "|=", "^=", "&="), "expression": fuzzExpression}, f);

export const fuzzComputedMemberAssignmentTarget = f =>
  ap(Shift.ComputedMemberAssignmentTarget, {"object": fuzzExpressionSuperProp, "expression": fuzzExpression}, f);

export const fuzzComputedMemberExpression = f =>
  ap(Shift.ComputedMemberExpression, {"object": fuzzExpressionSuperProp, "expression": fuzzExpression}, f);

export const fuzzComputedPropertyName = f =>
  ap(Shift.ComputedPropertyName, {"expression": fuzzExpression}, f);

export const fuzzConditionalExpression = f =>
  ap(Shift.ConditionalExpression, {"test": fuzzExpression, "consequent": fuzzExpression, "alternate": fuzzExpression}, f);

export const fuzzContinueStatement = f =>
  ap(Shift.ContinueStatement, {"label": f => f.loopLabels.length > 0 && f.rng.nextBoolean() ? oneOf(...f.loopLabels)(f) : null}, f);

export const fuzzDataProperty = f =>
  ap(Shift.DataProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "expression": fuzzExpression}, f);

export const fuzzDebuggerStatement = f =>
  ap(Shift.DebuggerStatement, {}, f);

export const fuzzDirective = (f = new FuzzerState, {allowUseStrict = true} = {}) => {
  let rawValue = allowUseStrict && f.rng.nextBoolean() ? 'use strict' : fuzzString(f);
  if (rawValue.match('"') && rawValue.match("'")) {
    let toReplace = f.rng.nextBoolean() ? '"' : "'";
    let regex = toReplace === '"' ? /((^|[^\\])(\\\\)*)"/g : /((^|[^\\])(\\\\)*)'/g; // Trust me, this was easier than generating them on the fly
    let orig;
    do {
      orig = rawValue;
      rawValue = rawValue.replace(regex, `$1\\${toReplace}`);
    } while (rawValue !== orig); // to handle e.g. '\"\"
  }
  let orig;
  do {
    orig = rawValue;
    rawValue = rawValue.replace(/((^|[^\\])(\\\\)*)([\r\n])/g, `$1\\$4`);
  } while (rawValue !== orig); // to handle e.g. \n\n
  rawValue = toRawValue(f, rawValue);
  if (!allowUseStrict && rawValue === 'use strict') {
    // This will almost never happen, but we should deal with it anyway.
    rawValue = '';
  }
  return new Shift.Directive({rawValue});
}

export const fuzzDoWhileStatement = f =>
  ap(Shift.DoWhileStatement, {"body": f => fuzzStatement(f.enterLoop(), {allowProperDeclarations: false, allowFunctionDeclarations: false}), "test": fuzzExpression}, f);

export const fuzzEmptyStatement = f =>
  ap(Shift.EmptyStatement, {}, f);

export const fuzzExport = f =>
  ap(Shift.Export, {"declaration": choose(fuzzClassDeclaration, fuzzFunctionDeclaration, fuzzVariableDeclaration)}, f);

export const fuzzExportAllFrom = f =>
  ap(Shift.ExportAllFrom, {"moduleSpecifier": fuzzString}, f);

export const fuzzExportDefault = f =>
  ap(Shift.ExportDefault, {"body": choose(fuzzClassDeclaration, fuzzExpression, fuzzFunctionDeclaration)}, f);

export const fuzzExportFrom = f =>
  ap(Shift.ExportFrom, {"namedExports": many(fuzzExportFromSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzExportFromSpecifier = f =>
  ap(Shift.ExportFromSpecifier, {"name": fuzzIdentifierName, "exportedName": opt(fuzzIdentifierName)}, f);

export const fuzzExportLocalSpecifier = f =>
  ap(Shift.ExportLocalSpecifier, {"name": fuzzIdentifierExpression, "exportedName": opt(fuzzIdentifierName)}, f);

export const fuzzExportLocals = f =>
  ap(Shift.ExportLocals, {"namedExports": many(fuzzExportLocalSpecifier)}, f);

export const fuzzExpressionStatement = f =>
  ap(Shift.ExpressionStatement, {"expression": fuzzExpression}, f);

export const fuzzForInStatement = (f = new FuzzerState) => {
  f = f.goDeeper();
  let left = f.rng.nextBoolean() ? fuzzVariableDeclaration(f, {inForInOfHead: true}) : fuzzAssignmentTarget(f);
  let right = fuzzExpression(f);
  let body = fuzzStatement(f.enterLoop(), {allowProperDeclarations: false, allowFunctionDeclarations: false});
  return new Shift.ForInStatement({left, right, body});
}

export const fuzzForOfStatement = (f = new FuzzerState) => {
  f = f.goDeeper();
  let left = f.rng.nextBoolean() ? fuzzVariableDeclaration(f, {inForInOfHead: true}) : fuzzAssignmentTarget(f);
  let right = fuzzExpression(f);
  let body = fuzzStatement(f.enterLoop(), {allowProperDeclarations: false, allowFunctionDeclarations: false});
  return new Shift.ForOfStatement({left, right, body});
}

export const fuzzForStatement = f =>
  ap(Shift.ForStatement, {"init": opt(choose(fuzzExpression, fuzzVariableDeclaration)), "test": opt(fuzzExpression), "update": opt(fuzzExpression), "body": f => fuzzStatement(f.enterLoop(), {allowProperDeclarations: false, allowFunctionDeclarations: false})}, f);

export const fuzzFormalParameters = (f = new FuzzerState, {hasStrictDirective = false} = {}) => {
  if (hasStrictDirective) {
    return new Shift.FormalParameters({items: many(fuzzBindingIdentifier)(f), rest: null}); // note that f.strict should be set by the callee in this case
  }
  f = f.goDeeper().disableYieldExpr();
  let items = many(choose(fuzzBindingWithDefault, fuzzBinding))(f);
  let rest = opt(fuzzBinding)(f);
  return new Shift.FormalParameters({items, rest});
}

export const fuzzFunctionBody = f =>
  ap(Shift.FunctionBody, {"directives": many(fuzzDirective), "statements": many(fuzzStatement)}, f);

export const fuzzFunctionDeclaration = (f = new FuzzerState, {allowProperDeclarations = true} = {}) => {
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let isGenerator = allowProperDeclarations && f.rng.nextBoolean();
  let name = fuzzBindingIdentifier(f);
  f = f.enterFunction({isGenerator, hasStrictDirective})
  let params = fuzzFormalParameters(f, {hasStrictDirective});
  let body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  return new Shift.FunctionDeclaration({isGenerator, name, params, body});
}

export const fuzzFunctionExpression = (f = new FuzzerState) => {
  f = f.clone();
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let isGenerator = f.rng.nextBoolean();
  if (isGenerator) {
    f.allowYieldIdentifier = false;
  }
  let name = f.rng.nextBoolean() ? fuzzBindingIdentifier(f) : null;
  f = f.enterFunction({isGenerator, hasStrictDirective})
  let params = fuzzFormalParameters(f, {hasStrictDirective});
  let body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  return new Shift.FunctionExpression({isGenerator, name, params, body});
}

export const fuzzGetter = (f = new FuzzerState, {isStatic = false, inClass = false} = {}) => {
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let name = f.rng.nextBoolean ? fuzzComputedPropertyName(f) : fuzzStaticPropertyName(f, {allowConstructor: !inClass, allowPrototype: !isStatic});
  f = f.enterFunction({isMethod: true, hasStrictDirective});
  f.allowSuperCall = false;
  f.allowSuperProp = true;
  let body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  return new Shift.Getter({name, body});
}

export const fuzzIdentifierExpression = f =>
  ap(Shift.IdentifierExpression, {"name": f => fuzzVariableName(f, false)}, f);

export const fuzzIfStatement = (f = new FuzzerState) => {
  f = f.goDeeper();
  let test = fuzzExpression(f);
  let alternate = !f.allowMissingElse || f.rng.nextBoolean() ? fuzzStatement(f, {allowProperDeclarations: false, allowFunctionDeclarations: !f.strict, allowLabeledFunctionDeclarations: false}) : null;
  if (alternate) {
    f.allowMissingElse = false;
  }
  let consequent = fuzzStatement(f, {allowProperDeclarations: false, allowFunctionDeclarations: !f.strict, allowLabeledFunctionDeclarations: false});
  return new Shift.IfStatement({test, consequent, alternate});
}

export const fuzzImport = f =>
  ap(Shift.Import, {"defaultBinding": opt(fuzzBindingIdentifier), "namedImports": many(fuzzImportSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzImportNamespace = f =>
  ap(Shift.ImportNamespace, {"defaultBinding": opt(fuzzBindingIdentifier), "namespaceBinding": fuzzBindingIdentifier, "moduleSpecifier": fuzzString}, f);

export const fuzzImportSpecifier = f =>
  ap(Shift.ImportSpecifier, {"name": opt(fuzzIdentifierName), "binding": fuzzBindingIdentifier}, f);

export const fuzzLabeledStatement = (f = new FuzzerState, {allowFunctionDeclarations = f.strict} = {}) => {
  f = f.goDeeper();
  let label = fuzzLabel(f);
  let body;
  f.labels = f.labels.concat([label]);
  if (f.rng.nextBoolean()) {
    f.loopLabels = f.loopLabels.concat([label]);
    body = choose(...loopFuzzers)(f);
  } else {
    body = fuzzStatement(f, {allowLoops: false, allowProperDeclarations: false, allowFunctionDeclarations});
  }
  return new Shift.LabeledStatement({label, body});
}

export const fuzzLiteralBooleanExpression = f =>
  ap(Shift.LiteralBooleanExpression, {"value": f => f.rng.nextBoolean()}, f);

export const fuzzLiteralInfinityExpression = f =>
  ap(Shift.LiteralInfinityExpression, {}, f);

export const fuzzLiteralNullExpression = f =>
  ap(Shift.LiteralNullExpression, {}, f);

export const fuzzLiteralNumericExpression = f =>
  ap(Shift.LiteralNumericExpression, {"value": choose(
    f => f.rng.nextInt(1e4),
    f => f.rng.nextInt(Math.pow(2, 53)),
    f => f.rng.nextDouble() * Math.pow(10, f.rng.nextInt(309)),
    f => parseFloat(("" + f.rng.nextDouble() * 1e4).slice(0, 7)),
    f => parseFloat(("" + f.rng.nextDouble()).slice(0, 4)),
    f => 0
  )}, f);

export const fuzzLiteralRegExpExpression = (f, canFuzzUnicode = false, bugAvoidance = new RegExpBugAvoidanceConfiguration({})) => {
  let isUnicode = canFuzzUnicode;
  return ap(Shift.LiteralRegExpExpression, {"pattern": f => fuzzRegExpPattern(f, isUnicode = isUnicode && f.rng.nextBoolean(), bugAvoidance).replace(/\//g, '\\$0'), "global": f => f.rng.nextBoolean(), "ignoreCase": f => f.rng.nextBoolean(), "multiLine": f => f.rng.nextBoolean(), "sticky": f => f.rng.nextBoolean(), "unicode": f => isUnicode, "dotAll": f => f.rng.nextBoolean()}, f);
}

export const fuzzLiteralStringExpression = f =>
  ap(Shift.LiteralStringExpression, {"value": fuzzString}, f);

export const fuzzMethod = (f = new FuzzerState, {isStatic = false, inClass = false, allowConstructor = true, constructorMayContainSuperCall = false} = {}) => { // isStatic implies inClass
  f = f.goDeeper();
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let isConstructor = inClass && allowConstructor && !isStatic && f.rng.nextBoolean();
  let isGenerator = !isConstructor && f.rng.nextBoolean();
  let name = isConstructor ? new Shift.StaticPropertyName({value: "constructor"}) : choose(fuzzComputedPropertyName, f => fuzzStaticPropertyName(f, {allowConstructor: !inClass, allowPrototype: !isStatic}))(f);
  f = f.enterFunction({isMethod: true, isGenerator, hasStrictDirective});
  f.allowSuperCall = isConstructor && constructorMayContainSuperCall;
  f.allowSuperProp = true;
  let params = fuzzFormalParameters(f, {hasStrictDirective});
  let body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  return new Shift.Method({isGenerator, name, params, body});
}

export const fuzzModule = (f = new FuzzerState) => {
  f = f.clone();
  f.strict = true;
  f.allowAwaitIdenifier = false;

  return ap(Shift.Module, {"directives": f => fuzzDirectives(f).directives, "items": many(choose(choose(fuzzExport, fuzzExportAllFrom, fuzzExportDefault, fuzzExportFrom, fuzzExportLocals), choose(fuzzImport, fuzzImportNamespace), fuzzStatement))}, f);
}

export const fuzzNewExpression = f =>
  ap(Shift.NewExpression, {"callee": fuzzExpression, "arguments": many(choose(fuzzExpression, fuzzSpreadElement))}, f);

export const fuzzNewTargetExpression = f =>
  ap(Shift.NewTargetExpression, {}, f);

export const fuzzObjectAssignmentTarget = f =>
  ap(Shift.ObjectAssignmentTarget, {"properties": many(choose(fuzzAssignmentTargetPropertyIdentifier, fuzzAssignmentTargetPropertyProperty))}, f);

export const fuzzObjectBinding = f =>
  ap(Shift.ObjectBinding, {"properties": many(choose(fuzzBindingPropertyIdentifier, fuzzBindingPropertyProperty))}, f);

export const fuzzObjectExpression = f =>
  ap(Shift.ObjectExpression, {"properties": many(choose(choose(fuzzDataProperty, choose(fuzzGetter, fuzzMethod, fuzzSetter)), fuzzShorthandProperty))}, f);

export const fuzzReturnStatement = f =>
  ap(Shift.ReturnStatement, {"expression": opt(fuzzExpression)}, f);

export const fuzzScript = (f = new FuzzerState) => {
  f = f.goDeeper();
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  f.strict = hasStrictDirective;
  return new Shift.Script({directives, statements: many(fuzzStatement)(f)})
}

export const fuzzSetter = (f = new FuzzerState, {isStatic = false, inClass = false} = {}) => {
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let name = f.rng.nextBoolean ? fuzzComputedPropertyName(f) : fuzzStaticPropertyName(f, {allowConstructor: !inClass, allowPrototype: !isStatic});
  f = f.enterFunction({isMethod: true, hasStrictDirective});
  f.allowSuperCall = false;
  f.allowSuperProp = true;
  let param = hasStrictDirective ? fuzzBindingIdentifier(f) : choose(fuzzBindingWithDefault, fuzzBinding)(f);
  let body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  return new Shift.Setter({name, param, body});
}

export const fuzzShorthandProperty = f =>
  ap(Shift.ShorthandProperty, {"name": fuzzIdentifierExpression}, f);

export const fuzzSpreadElement = f =>
  ap(Shift.SpreadElement, {"expression": fuzzExpression}, f);

export const fuzzStaticMemberAssignmentTarget = f =>
  ap(Shift.StaticMemberAssignmentTarget, {"object": fuzzExpressionSuperProp, "property": fuzzIdentifierName}, f);

export const fuzzStaticMemberExpression = f =>
  ap(Shift.StaticMemberExpression, {"object": fuzzExpressionSuperProp, "property": fuzzIdentifierName}, f);

export const fuzzStaticPropertyName = (f = new FuzzerState, {allowConstructor = true, allowPrototype = true} = {}) => { // todo avoid duplicate __proto__ simple properties
  let value;
  do {
    value = fuzzString(f);
  } while (!allowConstructor && value === 'constructor' || !allowPrototype && value === 'prototype');
  return new Shift.StaticPropertyName({value});
}

export const fuzzSuper = f =>
  ap(Shift.Super, {}, f);

export const fuzzSwitchCase = f =>
  ap(Shift.SwitchCase, {"test": fuzzExpression, "consequent": many(fuzzStatement)}, f);

export const fuzzSwitchDefault = f =>
  ap(Shift.SwitchDefault, {"consequent": many(fuzzStatement)}, f);

export const fuzzSwitchStatement = f =>
  ap(Shift.SwitchStatement, {"discriminant": fuzzExpression, "cases": many(fuzzSwitchCase)}, f.enterSwitch());

export const fuzzSwitchStatementWithDefault = f =>
  ap(Shift.SwitchStatementWithDefault, {"discriminant": fuzzExpression, "preDefaultCases": many(fuzzSwitchCase), "defaultCase": fuzzSwitchDefault, "postDefaultCases": many(fuzzSwitchCase)}, f.enterSwitch());

export const fuzzTemplateElement = (f = new FuzzerState) => {
  let rawValue = toRawValue(f, fuzzString(f));
  let orig;
  do {
    orig = rawValue;
    rawValue = rawValue.replace(/((^|[^\\])(\\\\)*)(`|\${)/g, '$1\\$4');
    rawValue = rawValue.replace(/((^|[^\\])(\\\\)*\\)(0(?=[0-7])|[1-7])/g, '$1\\$4');
  } while (rawValue !== orig);
  return new Shift.TemplateElement({rawValue});
}

export const fuzzTemplateExpression = (f = new FuzzerState) => {
  f = f.goDeeper();
  let tag = opt(fuzzExpression)(f);

  let exprs = many(fuzzExpression)(f);
  let elements = [fuzzTemplateElement(f)];
  for (let i = 0; i < exprs.length; ++i) {
    elements.push(exprs[i], fuzzTemplateElement(f));
  }
  return new Shift.TemplateExpression({tag, elements});
}

export const fuzzThisExpression = f =>
  ap(Shift.ThisExpression, {}, f);

export const fuzzThrowStatement = f =>
  ap(Shift.ThrowStatement, {"expression": fuzzExpression}, f);

export const fuzzTryCatchStatement = f =>
  ap(Shift.TryCatchStatement, {"body": fuzzBlock, "catchClause": fuzzCatchClause}, f);

export const fuzzTryFinallyStatement = f =>
  ap(Shift.TryFinallyStatement, {"body": fuzzBlock, "catchClause": opt(fuzzCatchClause), "finalizer": fuzzBlock}, f);

export const fuzzUnaryExpression = (f = new FuzzerState) => {
  f = f.goDeeper();
  let operator = oneOf("+", "-", "!", "~", "typeof", "void", "delete")(f);
  let operand = fuzzExpression(f, {allowIdentifierExpression: operator !== "delete" || !f.strict});
  return new Shift.UnaryExpression({operator, operand});
}

export const fuzzUpdateExpression = f =>
  ap(Shift.UpdateExpression, {"isPrefix": f => f.rng.nextBoolean(), "operator": oneOf("++", "--"), "operand": choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))}, f);

export const fuzzVariableDeclaration = (f = new FuzzerState, {allowProperDeclarations = true, inForInOfHead = false} = {}) => {
  f = f.goDeeper();
  let kind = allowProperDeclarations ? oneOf("var", "let", "const")(f) : "var";
  f.declKind = kind;
  let declarators;
  if (inForInOfHead) {
    declarators = [fuzzVariableDeclarator(f, {inForInOfHead})];
  } else {
    declarators = many1(fuzzVariableDeclarator)(f);
  }
  return new Shift.VariableDeclaration({kind, declarators});
}

export const fuzzVariableDeclarationStatement = (f = new FuzzerState, {allowProperDeclarations = true} = {}) => {
  f = f.goDeeper();
  let declaration = fuzzVariableDeclaration(f, {allowProperDeclarations});
  return new Shift.VariableDeclarationStatement({declaration});
}

export const fuzzVariableDeclarator = (f = new FuzzerState, {inForInOfHead = false} = {}) => {
  f = f.goDeeper();
  let binding = fuzzBinding(f);
  let init;
  if (inForInOfHead) {
    init = null;
  } else if (f.declKind === 'const' || binding.type === 'ArrayBinding' || binding.type === 'ObjectBinding') {
    init = fuzzExpression(f);
  } else {
    init = f.rng.nextBoolean() ? fuzzExpression(f) : null;
  }
  return new Shift.VariableDeclarator({binding, init});  
}

export const fuzzWhileStatement = f =>
  ap(Shift.WhileStatement, {"test": fuzzExpression, "body": f => fuzzStatement(f.enterLoop(), {allowProperDeclarations: false, allowFunctionDeclarations: false})}, f);

export const fuzzWithStatement = f =>
  ap(Shift.WithStatement, {"object": fuzzExpression, "body": f => fuzzStatement(f, {allowProperDeclarations: false, allowFunctionDeclarations: false})}, f);

export const fuzzYieldExpression = f =>
  ap(Shift.YieldExpression, {"expression": opt(fuzzExpression)}, f);

export const fuzzYieldGeneratorExpression = f =>
  ap(Shift.YieldGeneratorExpression, {"expression": fuzzExpression}, f);


const simpleExprFuzzers = [
  fuzzArrayExpression,
  fuzzArrowExpression,
  fuzzAssignmentExpression,
  fuzzBinaryExpression,
  fuzzCallExpression,
  fuzzClassExpression,
  fuzzCompoundAssignmentExpression,
  fuzzConditionalExpression,
  fuzzFunctionExpression,
  fuzzLiteralBooleanExpression,
  fuzzLiteralInfinityExpression,
  fuzzLiteralNullExpression,
  fuzzLiteralNumericExpression,
  fuzzLiteralRegExpExpression,
  fuzzLiteralStringExpression,
  fuzzNewExpression,
  fuzzObjectExpression,
  fuzzTemplateExpression,
  fuzzThisExpression,
  fuzzUnaryExpression,
  fuzzUpdateExpression,
  fuzzComputedMemberExpression,
  fuzzStaticMemberExpression
];

const yieldExprFuzzers = [
  fuzzYieldExpression,
  fuzzYieldGeneratorExpression
];

const simpleStmtFuzzers = [
  fuzzBlockStatement,
  fuzzDebuggerStatement,
  fuzzEmptyStatement,
  fuzzExpressionStatement,
  fuzzIfStatement,
  fuzzLabeledStatement,
  fuzzSwitchStatement,
  fuzzSwitchStatementWithDefault,
  fuzzThrowStatement,
  fuzzTryCatchStatement,
  fuzzTryFinallyStatement,
  fuzzVariableDeclarationStatement
];

const loopFuzzers = [
  fuzzDoWhileStatement,
  fuzzForInStatement,
  fuzzForOfStatement,
  fuzzForStatement,
  fuzzWhileStatement
];


const fuzzersPassingAllowMissingElse = [
  fuzzLabeledStatement,
  fuzzForStatement,
  fuzzForInStatement,
  fuzzForOfStatement,
  fuzzIfStatement,
  fuzzWhileStatement,
  fuzzWithStatement
];


const fuzzExpressionSuperProp = f =>
  f.allowSuperProp ? choose(fuzzExpression, fuzzSuper)(f) : fuzzExpression(f);

const fuzzExpressionSuperCall = f =>
  f.allowSuperCall ? choose(fuzzExpression, fuzzSuper)(f) : fuzzExpression(f);

const fuzzClassElements = (f, {allowConstructor}) => {
  let elements = [];
  if (f.tooDeep()) {
    return elements;
  }
  let count = f.rng.nextInt(MANY_BOUND + 1);
  while (count-- > 0) {
    let element = fuzzClassElement(f, {allowConstructor, constructorMayContainSuperCall: true});
    if (!element.isStatic && element.method.type === 'Method' && element.method.name.type === 'StaticPropertyName' && element.method.name.value === 'constructor') {
      allowConstructor = false;
    }
    elements.push(element);
  }
  return elements;
}

const fuzzDirectives = f => {
  f = f.clone();
  let hasStrictDirective = f.rng.nextBoolean();
  if (hasStrictDirective) {
    f.strict = true;
  }

  let directives = many(f => fuzzDirective(f, {allowUseStrict: hasStrictDirective}))(f);
  if (hasStrictDirective && !directives.some(d => d.rawValue === 'use strict')) {
    directives.push(new Shift.Directive({rawValue: 'use strict'}));
  }
  return {directives, hasStrictDirective};
}

const fuzzAssignmentTarget = f => {
  if (f.tooDeep() || f.rng.nextBoolean()) {
    return fuzzAssignmentTargetIdentifier(f);
  }
  return choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))(f);
}

const fuzzBinding = f => {
  if (f.tooDeep() || f.rng.nextBoolean()) {
    return fuzzBindingIdentifier(f);
  }
  return (f.rng.nextBoolean() ? fuzzArrayBinding : fuzzObjectBinding)(f);
}

export const fuzzProgram =
  choose(fuzzModule, fuzzScript);

export {fuzzProgram as default};

export const fuzzExpression = (f = new FuzzerState, {allowIdentifierExpression = true} = {}) => {
  if (f.tooDeep()) {
    return fuzzLeafExpression(f, {allowIdentifierExpression});
  }
  let fuzzers = simpleExprFuzzers;
  if (f.allowYieldExpr) {
    fuzzers = fuzzers.concat(yieldExprFuzzers);
  }
  if (f.allowNewTarget) {
    fuzzers = fuzzers.concat([fuzzNewTargetExpression]);
  }
  if (allowIdentifierExpression) {
    fuzzers = fuzzers.concat([fuzzIdentifierExpression]);
  }
  f = f.clone();
  f.declKind = null;

  return choose(...fuzzers)(f);
}

const fuzzLeafExpression = (f, {allowIdentifierExpression}) => {
  let fuzzers = [
    fuzzLiteralBooleanExpression,
    fuzzLiteralInfinityExpression,
    fuzzLiteralNullExpression,
    fuzzLiteralNumericExpression,
    fuzzLiteralRegExpExpression,
    fuzzLiteralStringExpression,
    fuzzThisExpression,
  ];
  if (allowIdentifierExpression) fuzzers.push(fuzzIdentifierExpression);
  if (f.allowNewTarget) fuzzers.push(fuzzNewTargetExpression);
  if (f.allowYieldExpr) fuzzers.push(fuzzYieldExpression);
  return choose(...fuzzers)(f);
};

export const fuzzStatement = (f = new FuzzerState, {allowLoops = true, allowProperDeclarations = true, allowFunctionDeclarations = true, allowLabeledFunctionDeclarations = !f.strict && allowFunctionDeclarations} = {}) => {
  if (f.tooDeep()) {
    return fuzzLeafStatement(f);
  }

  let fuzzers = [...simpleStmtFuzzers];
  if (allowLoops) {
    fuzzers.push(...loopFuzzers);
  }
  
  if (f.allowReturn) {
    fuzzers.push(fuzzReturnStatement);
  }
  if (f.inLoop) {
    fuzzers.push(fuzzBreakStatement, fuzzContinueStatement);
  } else if (f.allowBreak()) {
    fuzzers.push(fuzzBreakStatement);
  }
  if (allowProperDeclarations) {
    fuzzers.push(fuzzClassDeclaration, fuzzFunctionDeclaration);
  } else if (allowFunctionDeclarations) {
    fuzzers.push(fuzzFunctionDeclaration);
  }

  if (!f.strict) {
    fuzzers.push(fuzzWithStatement);
  }

  let fuzzer = oneOf(...fuzzers)(f);

  if (fuzzersPassingAllowMissingElse.indexOf(fuzzer) === -1) {
    f = f.enableMissingElse();
  }

  if (fuzzer === fuzzVariableDeclarationStatement) {
    return fuzzVariableDeclarationStatement(f, {allowProperDeclarations});
  }

  if (fuzzer === fuzzFunctionDeclaration) {
    return fuzzFunctionDeclaration(f, {allowProperDeclarations});
  }

  if (fuzzer === fuzzLabeledStatement) {
    return fuzzLabeledStatement(f, {allowFunctionDeclarations: allowLabeledFunctionDeclarations});
  }

  return fuzzer(f);
}

const fuzzLeafStatement = (f) => {
  let fuzzers = [fuzzDebuggerStatement, fuzzEmptyStatement];
  if (f.allowBreak()) fuzzers.push(fuzzBreakStatement);
  if (f.inLoop) fuzzers.push(fuzzContinueStatement);
  if (f.allowReturn) fuzzers.push(fuzzReturnStatement);
  return choose(...fuzzers)(f);
}
