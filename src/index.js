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
  'default', 'delete', 'do', 'else', 'enum', 'export', 'extends', 'finally',
  'for', 'function', 'if', 'import', 'in', 'instanceof', 'new', 'return',
  'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void', 'while',
  'with',
  // future reserved words
  'class', 'const', 'enum', 'export', 'extends', 'implements', 'import',
  'interface', 'let', 'package', 'private', 'protected', 'public', 'static',
  'super', 'yield',
  // null, booleans
  'null', 'true', 'false',
]; // todo strict mode reserved words

function identifierStart(fuzzerState) { // todo. see also https://gist.github.com/mathiasbynens/6334847#file-javascript-identifier-regex-js-L65-L105
  return String.fromCharCode(97 + fuzzerState.rng.nextInt(25));
}

const identifierPart = identifierStart; // todo
const MAX_IDENT_LENGTH = 15;

function genIdentifierString(f) {
  while (true) {
    let possibleIdentifier = identifierStart(f) + manyN(MAX_IDENT_LENGTH)(identifierPart)(f).join("");
    if (RESERVED.indexOf(possibleIdentifier) < 0) return possibleIdentifier;
  }
}

const fuzzIdentifier = genIdentifierString;

const fuzzIdentifierName = choose(genIdentifierString, oneOf(...RESERVED));

const fuzzString = f => f.rng.nextString(); // todo most uses require more specificity than this

// export const fuzzers = Object.create(null);

export const fuzzArrayAssignmentTarget = f =>
  ap(Shift.ArrayAssignmentTarget, {"elements": many(opt(choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget)))))), "rest": opt(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzArrayBinding = f =>
  ap(Shift.ArrayBinding, {"elements": many(opt(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding))))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f); // todo guard depth? possibly via fuzzBinding / fuzzAssignmentTarget

export const fuzzArrayExpression = f =>
  ap(Shift.ArrayExpression, {"elements": many(opt(choose(fuzzExpression, fuzzSpreadElement)))}, f);

export const fuzzArrowExpression = f =>
  ap(Shift.ArrowExpression, {"params": fuzzFormalParameters, "body": choose(fuzzExpression, fuzzFunctionBody)}, f);

export const fuzzAssignmentExpression = f =>
  ap(Shift.AssignmentExpression, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "expression": fuzzExpression}, f);

export const fuzzAssignmentTargetIdentifier = f =>
  ap(Shift.AssignmentTargetIdentifier, {"name": fuzzIdentifier}, f);

export const fuzzAssignmentTargetPropertyIdentifier = f =>
  ap(Shift.AssignmentTargetPropertyIdentifier, {"binding": fuzzAssignmentTargetIdentifier, "init": opt(fuzzExpression)}, f);

export const fuzzAssignmentTargetPropertyProperty = f =>
  ap(Shift.AssignmentTargetPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzAssignmentTargetWithDefault = f =>
  ap(Shift.AssignmentTargetWithDefault, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "init": fuzzExpression}, f);

export const fuzzBinaryExpression = f =>
  ap(Shift.BinaryExpression, {"left": fuzzExpression, "operator": oneOf("==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof", "<<", ">>", ">>>", "+", "-", "*", "/", "%", "**", ",", "||", "&&", "|", "^", "&"), "right": fuzzExpression}, f);

export const fuzzBindingIdentifier = f =>
  ap(Shift.BindingIdentifier, {"name": fuzzIdentifier}, f);

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
  ap(Shift.BreakStatement, {"label": opt(fuzzIdentifier)}, f);

export const fuzzCallExpression = f =>
  ap(Shift.CallExpression, {"callee": fuzzExpressionSuperCall, "arguments": many(choose(fuzzExpression, fuzzSpreadElement))}, f);

export const fuzzCatchClause = f =>
  ap(Shift.CatchClause, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "body": fuzzBlock}, f);

export const fuzzClassDeclaration = f =>
  ap(Shift.ClassDeclaration, {"name": fuzzBindingIdentifier, "super": opt(fuzzExpression), "elements": many(fuzzClassElement)}, f);

export const fuzzClassElement = f =>
  ap(Shift.ClassElement, {"isStatic": f => f.rng.nextBoolean(), "method": choose(fuzzGetter, fuzzMethod, fuzzSetter)}, f);

export const fuzzClassExpression = f =>
  ap(Shift.ClassExpression, {"name": opt(fuzzBindingIdentifier), "super": opt(fuzzExpression), "elements": many(fuzzClassElement)}, f);

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
  ap(Shift.ContinueStatement, {"label": opt(fuzzIdentifier)}, f);

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

export const fuzzFormalParameters = (f = new FuzzerState) =>
  ap(Shift.FormalParameters, {"items": many(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f);

export const fuzzFunctionBody = f =>
  ap(Shift.FunctionBody, {"directives": many(fuzzDirective), "statements": many(fuzzStatement)}, f);

export const fuzzFunctionDeclaration = f =>
  ap(Shift.FunctionDeclaration, {"isGenerator": f => f.rng.nextBoolean(), "name": fuzzBindingIdentifier, "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzFunctionExpression = f =>
  ap(Shift.FunctionExpression, {"isGenerator": f => f.rng.nextBoolean(), "name": opt(fuzzBindingIdentifier), "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzGetter = f =>
  ap(Shift.Getter, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "body": fuzzFunctionBody}, f);

export const fuzzIdentifierExpression = f =>
  ap(Shift.IdentifierExpression, {"name": fuzzIdentifier}, f);

export const fuzzIfStatement = f =>
  ap(Shift.IfStatement, {"test": fuzzExpression, "consequent": fuzzStatement, "alternate": opt(fuzzStatement)}, f);

export const fuzzImport = f =>
  ap(Shift.Import, {"defaultBinding": opt(fuzzBindingIdentifier), "namedImports": many(fuzzImportSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzImportNamespace = f =>
  ap(Shift.ImportNamespace, {"defaultBinding": opt(fuzzBindingIdentifier), "namespaceBinding": fuzzBindingIdentifier, "moduleSpecifier": fuzzString}, f);

export const fuzzImportSpecifier = f =>
  ap(Shift.ImportSpecifier, {"name": opt(fuzzIdentifierName), "binding": fuzzBindingIdentifier}, f);

export const fuzzLabeledStatement = f =>
  ap(Shift.LabeledStatement, {"label": fuzzIdentifier, "body": fuzzStatement}, f);

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

export const fuzzMethod = f =>
  ap(Shift.Method, {"isGenerator": f => f.rng.nextBoolean(), "name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzModule = f =>
  ap(Shift.Module, {"directives": many(fuzzDirective), "items": many(choose(choose(fuzzExport, fuzzExportAllFrom, fuzzExportDefault, fuzzExportFrom, fuzzExportLocals), choose(fuzzImport, fuzzImportNamespace), fuzzStatement))}, f);

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

export const fuzzScript = f =>
  ap(Shift.Script, {"directives": many(fuzzDirective), "statements": many(fuzzStatement)}, f);

export const fuzzSetter = f =>
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

export const fuzzVariableDeclaration = f =>
  ap(Shift.VariableDeclaration, {"kind": oneOf("var", "let", "const"), "declarators": many(fuzzVariableDeclarator)}, f);

export const fuzzVariableDeclarationStatement = f =>
  ap(Shift.VariableDeclarationStatement, {"declaration": fuzzVariableDeclaration}, f);

export const fuzzVariableDeclarator = f =>
  ap(Shift.VariableDeclarator, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "init": opt(fuzzExpression)}, f);

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
  fuzzVariableDeclarationStatement,
  fuzzWithStatement
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

  return choose(...fuzzers)(f);
}

export const fuzzStatement = (f = new FuzzerState) => {
  if (f.tooDeep()) {
    return fuzzEmptyStatement(f); // todo all length-one options
  }

  let fuzzers = simpleStmtFuzzers.concat(loopFuzzers); // [...simpleStmtFuzzers, ...loopFuzzers] is more elegant, but maybe slower
  
  if (f.allowReturn) {
    fuzzers.push(fuzzReturnStatement);
  }
  if (f.inIteration) {
    fuzzers.push(fuzzBreakStatement, fuzzContinueStatement);
  } else if (f.allowBreak()) {
    fuzzers.push(fuzzBreakStatement);
  }
  if (f.allowProperDeclarations) {
    fuzzers.push(fuzzClassDeclaration, fuzzFunctionDeclaration);
  } else if (f.allowFunctionDeclarations) {
    fuzzers.push(fuzzFunctionDeclaration);
  }

  let fuzzer = oneOf(...fuzzers)(f);

  if (fuzzersPassingAllowMissingElse.indexOf(fuzzer) === -1) {
    f = f.enableMissingElse();
  }

  if (fuzzer !== fuzzVariableDeclarationStatement && fuzzer !== fuzzFunctionDeclaration) {
    f = f.enableDeclarations(); // those two need to know to avoid let and generators
  }

  return fuzzer(f);
};
