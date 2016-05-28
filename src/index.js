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
import { ap, choose, guardDepth, many, many1, manyN, oneOf, opt, } from "./combinators";



const RESERVED =  [ // todo import this
  // keywords
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
  'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
  'for', 'function', 'if', 'import', 'in', 'instanceof', 'new', 'return',
  'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void', 'while',
  'with',
  // null, booleans
  'null', 'true', 'false',
];

const STRICT_FORBIDDEN = [
  'implements', 'package', 'protected', 'interface', 'private', 'public',
  'static', 'enum'
];

const ALL_KNOWN_WORDS = [...RESERVED, ...STRICT_FORBIDDEN, 'let', 'yield', 'await', 'eval', 'arguments'];

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
  let forbiddenNames = [...RESERVED];
  if (f.strict) {
    forbiddenNames.push(...STRICT_FORBIDDEN, 'let', 'yield');
  } else {
    interestingNames.push(...STRICT_FORBIDDEN, 'let');
    (!f.allowYieldIdentifier ? forbiddenNames : interestingNames).push('yield');
  }
  (!f.allowAwaitIdenifier ? forbiddenNames : interestingNames).push('await');

  return fuzzIdentifier(f, interestingNames, forbiddenNames);
}

const fuzzIdentifier = (f, interestingNames, forbiddenNames) => {
  if (interestingNames.length > 0 && f.nextBoolean()) {
    return oneOf(...interestingNames)(f);
  }

  while (true) {
    let possibleIdentifier = genIdentifierString(f);
    if (forbiddenNames.indexOf(possibleIdentifier) < 0) return possibleIdentifier;
  }
}

const fuzzIdentifierName = choose(genIdentifierString, oneOf(...ALL_KNOWN_WORDS));;

const fuzzString = f => f.rng.nextString(); // todo most uses require more specificity than this

// export const fuzzers = Object.create(null);

export const fuzzArrayAssignmentTarget = f =>
  ap(Shift.ArrayAssignmentTarget, {"elements": many(opt(choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget)))))), "rest": opt(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzArrayBinding = f =>
  ap(Shift.ArrayBinding, {"elements": many(opt(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding))))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f); // todo guard depth? possibly via fuzzBinding / fuzzAssignmentTarget

export const fuzzArrayExpression = f =>
  ap(Shift.ArrayExpression, {"elements": many(opt(choose(fuzzExpression, fuzzSpreadElement)))}, f);

export const fuzzArrowExpression = (f = new FuzzerState) => {
  let isConsise = f.nextBoolean();
  let params, body;
  if (!isConsise) {
    let {directives, hasStrictDirective} = fuzzDirectives(f);
    f = f.goDeeper().enterFunction({isArrow: true, hasStrictDirective});
    params = fuzzFormalParameters(f, {hasStrictDirective});
    body = new Shift.FunctionBody({directives, statements: many(fuzzStatement)(f.goDeeper())});
  } else {
    f = f.goDeeper().enterFunction({isArrow: true});
    params = fuzzFormalParameters(f);
    body = fuzzExpression(f);
  }
  return new Shift.ArrowExpression({params, body});
}

export const fuzzAssignmentExpression = f =>
  ap(Shift.AssignmentExpression, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "expression": fuzzExpression}, f);

export const fuzzAssignmentTargetIdentifier = f =>
  ap(Shift.AssignmentTargetIdentifier, {"name": f => fuzzVariableName(f, true)}, f);

export const fuzzAssignmentTargetPropertyIdentifier = f =>
  ap(Shift.AssignmentTargetPropertyIdentifier, {"binding": fuzzAssignmentTargetIdentifier, "init": opt(fuzzExpression)}, f);

export const fuzzAssignmentTargetPropertyProperty = f =>
  ap(Shift.AssignmentTargetPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzAssignmentTargetWithDefault = f =>
  ap(Shift.AssignmentTargetWithDefault, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "init": fuzzExpression}, f);

export const fuzzBinaryExpression = f =>
  ap(Shift.BinaryExpression, {"left": fuzzExpression, "operator": oneOf("==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof", "<<", ">>", ">>>", "+", "-", "*", "/", "%", "**", ",", "||", "&&", "|", "^", "&"), "right": fuzzExpression}, f);

export const fuzzBindingIdentifier = f =>
  ap(Shift.BindingIdentifier, {"name": f => fuzzVariableName(f, true)}, f);

export const fuzzBindingPropertyIdentifier = f =>
  ap(Shift.BindingPropertyIdentifier, {"binding": fuzzBindingIdentifier, "init": opt(fuzzExpression)}, f);

export const fuzzBindingPropertyProperty = f =>
  ap(Shift.BindingPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f);

export const fuzzBindingWithDefault = f =>
  ap(Shift.BindingWithDefault, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "init": fuzzExpression}, f);

export const fuzzBlock = f =>
  ap(Shift.Block, {"statements": many(fuzzStatement)}, f);

export const fuzzBlockStatement = f =>
  ap(Shift.BlockStatement, {"block": fuzzBlock}, f);

export const fuzzBreakStatement = f =>
  ap(Shift.BreakStatement, {"label": f => f.labels.length > 0 && (!(f.inIteration || f.inSwitch) || f.nextBoolean()) ? oneOf(...f.labels)(f) : null}, f);

export const fuzzCallExpression = f =>
  ap(Shift.CallExpression, {"callee": fuzzExpressionSuperCall, "arguments": many(choose(fuzzExpression, fuzzSpreadElement))}, f);

export const fuzzCatchClause = f =>
  ap(Shift.CatchClause, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "body": fuzzBlock}, f);

export const fuzzClassDeclaration = (f = new FuzzerState) => {
  f = f.goDeeper();
  f.inIteration = f.inSwitch = false;
  let name = fuzzBindingIdentifier(f);
  f.strict = true;
  let _super = opt(fuzzExpression)(f);
  let elements = many(f => fuzzClassElement(f, {constructorMayContainSuperCall: true}))(f);
  return new Shift.ClassDeclaration({name, "super": _super, elements});
}

export const fuzzClassElement = (f = new FuzzerState, {constructorMayContainSuperCall = false} = {}) => {
  f = f.goDeeper();
  let isStatic = f.rng.nextBoolean();
  let method = choose(f => fuzzGetter(f, {isStatic, inClass: true}), f => fuzzMethod(f, {isStatic, inClass: true, constructorMayContainSuperCall}), f => fuzzSetter({isStatic, inClass: true}))(f);
  return new Shift.ClassElement({isStatic, method});
}

export const fuzzClassExpression = (f = new FuzzerState) => {
  f = f.goDeeper();
  f.inIteration = f.inSwitch = false;
  let name = opt(fuzzBindingIdentifier)(f);
  f.strict = true;
  let _super = opt(fuzzExpression)(f);
  let elements = many(f => fuzzClassElement(f, {constructorMayContainSuperCall: true}))(f);
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
  ap(Shift.ContinueStatement, {"label": f => f.loopLabels.length > 0 && f.nextBoolean() ? oneOf(...f.iterationLabels)(f) : null}, f);

export const fuzzDataProperty = f =>
  ap(Shift.DataProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "expression": fuzzExpression}, f);

export const fuzzDebuggerStatement = f =>
  ap(Shift.DebuggerStatement, {}, f);

export const fuzzDirective = f =>
  ap(Shift.Directive, {"rawValue": fuzzString}, f);

export const fuzzDoWhileStatement = f =>
  ap(Shift.DoWhileStatement, {"body": fuzzStatement, "test": fuzzExpression}, f);

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

export const fuzzForInStatement = f =>
  ap(Shift.ForInStatement, {"left": choose(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), fuzzVariableDeclaration), "right": fuzzExpression, "body": fuzzStatement}, f);

export const fuzzForOfStatement = f =>
  ap(Shift.ForOfStatement, {"left": choose(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), fuzzVariableDeclaration), "right": fuzzExpression, "body": fuzzStatement}, f);

export const fuzzForStatement = f =>
  ap(Shift.ForStatement, {"init": opt(choose(fuzzExpression, fuzzVariableDeclaration)), "test": opt(fuzzExpression), "update": opt(fuzzExpression), "body": fuzzStatement}, f);

export const fuzzFormalParameters = (f = new FuzzerState, {hasStrictDirective = false} = {}) => {
  if (hasStrictDirective) {
    return new Shift.FormalParameters({items: many(fuzzBindingIdentifier)(f), rest: null}); // note that f.strict should be set by the callee in this case
  }
  return ap(Shift.FormalParameters, {"items": many(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f.disableYieldExpr());
}

export const fuzzFunctionBody = f =>
  ap(Shift.FunctionBody, {"directives": many(fuzzDirective), "statements": many(fuzzStatement)}, f);

export const fuzzFunctionDeclaration = (f = new FuzzerState, {allowProperDeclarations = true} = {}) =>
  ap(Shift.FunctionDeclaration, {"isGenerator": f => f.rng.nextBoolean(), "name": fuzzBindingIdentifier, "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzFunctionExpression = f =>
  ap(Shift.FunctionExpression, {"isGenerator": f => f.rng.nextBoolean(), "name": opt(fuzzBindingIdentifier), "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzGetter = (f = new FuzzerState, {isStatic = false, inClass = false} = {}) =>
  ap(Shift.Getter, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "body": fuzzFunctionBody}, f);

export const fuzzIdentifierExpression = f =>
  ap(Shift.IdentifierExpression, {"name": f => fuzzVariableName(f, false)}, f);

export const fuzzIfStatement = f =>
  ap(Shift.IfStatement, {"test": fuzzExpression, "consequent": fuzzStatement, "alternate": opt(fuzzStatement)}, f);

export const fuzzImport = f =>
  ap(Shift.Import, {"defaultBinding": opt(fuzzBindingIdentifier), "namedImports": many(fuzzImportSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzImportNamespace = f =>
  ap(Shift.ImportNamespace, {"defaultBinding": opt(fuzzBindingIdentifier), "namespaceBinding": fuzzBindingIdentifier, "moduleSpecifier": fuzzString}, f);

export const fuzzImportSpecifier = f =>
  ap(Shift.ImportSpecifier, {"name": opt(fuzzIdentifierName), "binding": fuzzBindingIdentifier}, f);

export const fuzzLabeledStatement = (f = new FuzzerState) => {
  f = f.goDeeper();
  let label = fuzzLabel(f);
  let body;
  f.labels = f.labels.concat([label]);
  if (f.nextBoolean()) {
    f.iterationLabels = f.iterationLabels.concat([label]);
    body = choose(loopFuzzers)(f);
  } else {
    body = fuzzStatement(f, {allowLoops: false, allowProperDeclarations: false, allowFunctionDeclarations: f.isStrict});
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

export const fuzzLiteralRegExpExpression = f =>
  ap(Shift.LiteralRegExpExpression, {"pattern": fuzzString, "global": f => f.rng.nextBoolean(), "ignoreCase": f => f.rng.nextBoolean(), "multiLine": f => f.rng.nextBoolean(), "sticky": f => f.rng.nextBoolean(), "unicode": f => f.rng.nextBoolean()}, f);

export const fuzzLiteralStringExpression = f =>
  ap(Shift.LiteralStringExpression, {"value": fuzzString}, f);

export const fuzzMethod = (f = new FuzzerState, {isStatic = false, constructorMayContainSuperCall = false} = {}) => {
  f = f.goDeeper();
  let {directives, hasStrictDirective} = fuzzDirectives(f);
  let isConstructor = !isStatic && f.nextBoolean(.3); // todo prohibit duplicate constructors
  let isGenerator = !isConstructor && f.nextBoolean();
  let name = isConstructor ? new Shift.StaticPropertyName({value: "constructor"}) : choose(fuzzComputedPropertyName, fuzzStaticPropertyName)(f); // todo prohibit non-static methods named constructor and static methods named prototype
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
  ap(Shift.Module, {"directives": many(fuzzDirective), "items": many(choose(choose(fuzzExport, fuzzExportAllFrom, fuzzExportDefault, fuzzExportFrom, fuzzExportLocals), choose(fuzzImport, fuzzImportNamespace), fuzzStatement))}, f);
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

export const fuzzSetter = (f = new FuzzerState, {isStatic = false, inClass = false} = {}) =>
  ap(Shift.Setter, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "param": choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding))), "body": fuzzFunctionBody}, f);

export const fuzzShorthandProperty = f =>
  ap(Shift.ShorthandProperty, {"name": fuzzIdentifierExpression}, f);

export const fuzzSpreadElement = f =>
  ap(Shift.SpreadElement, {"expression": fuzzExpression}, f);

export const fuzzStaticMemberAssignmentTarget = f =>
  ap(Shift.StaticMemberAssignmentTarget, {"object": fuzzExpressionSuperProp, "property": fuzzIdentifierName}, f);

export const fuzzStaticMemberExpression = f =>
  ap(Shift.StaticMemberExpression, {"object": fuzzExpressionSuperProp, "property": fuzzIdentifierName}, f);

export const fuzzStaticPropertyName = f =>
  ap(Shift.StaticPropertyName, {"value": fuzzString}, f);

export const fuzzSuper = f =>
  ap(Shift.Super, {}, f);

export const fuzzSwitchCase = f =>
  ap(Shift.SwitchCase, {"test": fuzzExpression, "consequent": many(fuzzStatement)}, f);

export const fuzzSwitchDefault = f =>
  ap(Shift.SwitchDefault, {"consequent": many(fuzzStatement)}, f);

export const fuzzSwitchStatement = f =>
  ap(Shift.SwitchStatement, {"discriminant": fuzzExpression, "cases": many(fuzzSwitchCase)}, f);

export const fuzzSwitchStatementWithDefault = f =>
  ap(Shift.SwitchStatementWithDefault, {"discriminant": fuzzExpression, "preDefaultCases": many(fuzzSwitchCase), "defaultCase": fuzzSwitchDefault, "postDefaultCases": many(fuzzSwitchCase)}, f);

export const fuzzTemplateElement = f =>
  ap(Shift.TemplateElement, {"rawValue": fuzzString}, f);

export const fuzzTemplateExpression = f =>
  ap(Shift.TemplateExpression, {"tag": opt(fuzzExpression), "elements": many(choose(fuzzExpression, fuzzTemplateElement))}, f); // todo just generate many expressions and then that number + 1 TemplateElements

export const fuzzThisExpression = f =>
  ap(Shift.ThisExpression, {}, f);

export const fuzzThrowStatement = f =>
  ap(Shift.ThrowStatement, {"expression": fuzzExpression}, f);

export const fuzzTryCatchStatement = f =>
  ap(Shift.TryCatchStatement, {"body": fuzzBlock, "catchClause": fuzzCatchClause}, f);

export const fuzzTryFinallyStatement = f =>
  ap(Shift.TryFinallyStatement, {"body": fuzzBlock, "catchClause": opt(fuzzCatchClause), "finalizer": fuzzBlock}, f);

export const fuzzUnaryExpression = f =>
  ap(Shift.UnaryExpression, {"operator": oneOf("+", "-", "!", "~", "typeof", "void", "delete"), "operand": fuzzExpression}, f);

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

export const fuzzVariableDeclarationStatement = (f = new FuzzerState, {allowProperDeclarations = true} = {}) =>
  ap(Shift.VariableDeclarationStatement, {"declaration": fuzzVariableDeclaration}, f);

export const fuzzVariableDeclarator = (f = new FuzzerState, {inForInOfHead = false} = {}) =>
  ap(Shift.VariableDeclarator, {
    "binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)),
    "init": inForInOfHead ? f => null : (f.declKind === 'const' ? fuzzExpression : opt(fuzzExpression))
  }, f);

export const fuzzWhileStatement = f =>
  ap(Shift.WhileStatement, {"test": fuzzExpression, "body": fuzzStatement}, f);

export const fuzzWithStatement = f =>
  ap(Shift.WithStatement, {"object": fuzzExpression, "body": fuzzStatement}, f);

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
  fuzzIdentifierExpression,
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

const fuzzDirectives = f => {
  return {directives: [], hasStrictDirective: false}; // todo
}

export const fuzzProgram =
  choose(fuzzModule, fuzzScript);

export const fuzzExpression = (f = new FuzzerState) => {
  if (f.tooDeep()) {
    return fuzzLiteralNullExpression(f); // todo all length-one options
  }
  let fuzzers = simpleExprFuzzers;
  if (f.allowYieldExpr) {
    fuzzers = fuzzers.concat(yieldExprFuzzers);
  }
  if (f.allowNewTarget) {
    fuzzers = fuzzers.concat([fuzzNewTargetExpression]);
  }
  f = f.clone(); // todo method
  f.declKind = null;

  return choose(...fuzzers)(f);
}

export const fuzzStatement = (f = new FuzzerState, {allowLoops = true, allowProperDeclarations = true, allowFunctionDeclarations = true}) => {
  if (f.tooDeep()) {
    return fuzzEmptyStatement(f); // todo all length-one options
  }

  let fuzzers = [...simpleStmtFuzzers];
  if (allowLoops) {
    fuzzers.push(...loopFuzzers);
  }
  
  if (f.allowReturn) {
    fuzzers.push(fuzzReturnStatement);
  }
  if (f.inIteration) {
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

  return fuzzer(f);
};
