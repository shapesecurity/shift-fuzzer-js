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

import * as Shift from "shift-ast";

import FuzzerState from "./fuzzer-state";
import { ap, choose, guardDepth, many, many1, manyN, oneOf, opt, } from "./combinators";

export const fuzzString =
  () => null

// export const fuzzers = Object.create(null);

export const fuzzExpression =
  f => guardDepth(
    fuzzLiteralNullExpression,
    choose(
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
      fuzzNewTargetExpression,
      fuzzObjectExpression,
      fuzzTemplateExpression,
      fuzzThisExpression,
      fuzzUnaryExpression,
      fuzzUpdateExpression,
      fuzzYieldExpression,
      fuzzYieldGeneratorExpression,
      fuzzComputedMemberExpression,
      fuzzStaticMemberExpression
    )
  )(f);

export const fuzzStatement =
  f => guardDepth(
    fuzzEmptyStatement,
    choose(
      fuzzBlockStatement,
      fuzzBreakStatement,
      fuzzClassDeclaration,
      fuzzContinueStatement,
      fuzzDebuggerStatement,
      fuzzEmptyStatement,
      fuzzExpressionStatement,
      fuzzFunctionDeclaration,
      fuzzIfStatement,
      fuzzLabeledStatement,
      fuzzReturnStatement,
      fuzzSwitchStatement,
      fuzzSwitchStatementWithDefault,
      fuzzThrowStatement,
      fuzzTryCatchStatement,
      fuzzTryFinallyStatement,
      fuzzVariableDeclarationStatement,
      fuzzWithStatement,
      fuzzDoWhileStatement,
      fuzzForInStatement,
      fuzzForOfStatement,
      fuzzForStatement,
      fuzzWhileStatement
    )
  )(f);


export const fuzzArrayAssignmentTarget = f =>
  ap(Shift.ArrayAssignmentTarget, {"elements": many(opt(choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget)))))), "rest": opt(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzArrayBinding = f =>
  ap(Shift.ArrayBinding, {"elements": many(opt(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding))))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f);

export const fuzzArrayExpression = f =>
  ap(Shift.ArrayExpression, {"elements": many(opt(choose(f => fuzzExpression(f), fuzzSpreadElement)))}, f);

export const fuzzArrowExpression = f =>
  ap(Shift.ArrowExpression, {"params": fuzzFormalParameters, "body": choose(f => fuzzExpression(f), fuzzFunctionBody)}, f);

export const fuzzAssignmentExpression = f =>
  ap(Shift.AssignmentExpression, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "expression": f => fuzzExpression(f)}, f);

export const fuzzAssignmentTargetIdentifier = f =>
  ap(Shift.AssignmentTargetIdentifier, {"name": fuzzString}, f);

export const fuzzAssignmentTargetPropertyIdentifier = f =>
  ap(Shift.AssignmentTargetPropertyIdentifier, {"binding": fuzzAssignmentTargetIdentifier, "init": opt(f => fuzzExpression(f))}, f);

export const fuzzAssignmentTargetPropertyProperty = f =>
  ap(Shift.AssignmentTargetPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzAssignmentTargetWithDefault, choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))))}, f);

export const fuzzAssignmentTargetWithDefault = f =>
  ap(Shift.AssignmentTargetWithDefault, {"binding": choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), "init": f => fuzzExpression(f)}, f);

export const fuzzBinaryExpression = f =>
  ap(Shift.BinaryExpression, {"left": f => fuzzExpression(f), "operator": oneOf("==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof", "<<", ">>", ">>>", "+", "-", "*", "/", "%", "**", ",", "||", "&&", "|", "^", "&"), "right": f => fuzzExpression(f)}, f);

export const fuzzBindingIdentifier = f =>
  ap(Shift.BindingIdentifier, {"name": fuzzString}, f);

export const fuzzBindingPropertyIdentifier = f =>
  ap(Shift.BindingPropertyIdentifier, {"binding": fuzzBindingIdentifier, "init": opt(f => fuzzExpression(f))}, f);

export const fuzzBindingPropertyProperty = f =>
  ap(Shift.BindingPropertyProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "binding": choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f);

export const fuzzBindingWithDefault = f =>
  ap(Shift.BindingWithDefault, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "init": f => fuzzExpression(f)}, f);

export const fuzzBlock = f =>
  ap(Shift.Block, {"statements": many(f => fuzzStatement(f))}, f);

export const fuzzBlockStatement = f =>
  ap(Shift.BlockStatement, {"block": fuzzBlock}, f);

export const fuzzBreakStatement = f =>
  ap(Shift.BreakStatement, {"label": opt(fuzzString)}, f);

export const fuzzCallExpression = f =>
  ap(Shift.CallExpression, {"callee": choose(f => fuzzExpression(f), fuzzSuper), "arguments": many(choose(f => fuzzExpression(f), fuzzSpreadElement))}, f);

export const fuzzCatchClause = f =>
  ap(Shift.CatchClause, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "body": fuzzBlock}, f);

export const fuzzClassDeclaration = f =>
  ap(Shift.ClassDeclaration, {"name": fuzzBindingIdentifier, "super": opt(f => fuzzExpression(f)), "elements": many(fuzzClassElement)}, f);

export const fuzzClassElement = f =>
  ap(Shift.ClassElement, {"isStatic": f => f.rng.nextBoolean(), "method": choose(fuzzGetter, fuzzMethod, fuzzSetter)}, f);

export const fuzzClassExpression = f =>
  ap(Shift.ClassExpression, {"name": opt(fuzzBindingIdentifier), "super": opt(f => fuzzExpression(f)), "elements": many(fuzzClassElement)}, f);

export const fuzzCompoundAssignmentExpression = f =>
  ap(Shift.CompoundAssignmentExpression, {"binding": choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget)), "operator": oneOf("+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "|=", "^=", "&="), "expression": f => fuzzExpression(f)}, f);

export const fuzzComputedMemberAssignmentTarget = f =>
  ap(Shift.ComputedMemberAssignmentTarget, {"object": choose(f => fuzzExpression(f), fuzzSuper), "expression": f => fuzzExpression(f)}, f);

export const fuzzComputedMemberExpression = f =>
  ap(Shift.ComputedMemberExpression, {"object": choose(f => fuzzExpression(f), fuzzSuper), "expression": f => fuzzExpression(f)}, f);

export const fuzzComputedPropertyName = f =>
  ap(Shift.ComputedPropertyName, {"expression": f => fuzzExpression(f)}, f);

export const fuzzConditionalExpression = f =>
  ap(Shift.ConditionalExpression, {"test": f => fuzzExpression(f), "consequent": f => fuzzExpression(f), "alternate": f => fuzzExpression(f)}, f);

export const fuzzContinueStatement = f =>
  ap(Shift.ContinueStatement, {"label": opt(fuzzString)}, f);

export const fuzzDataProperty = f =>
  ap(Shift.DataProperty, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "expression": f => fuzzExpression(f)}, f);

export const fuzzDebuggerStatement = f =>
  ap(Shift.DebuggerStatement, {}, f);

export const fuzzDirective = f =>
  ap(Shift.Directive, {"rawValue": fuzzString}, f);

export const fuzzDoWhileStatement = f =>
  ap(Shift.DoWhileStatement, {"body": f => fuzzStatement(f), "test": f => fuzzExpression(f)}, f);

export const fuzzEmptyStatement = f =>
  ap(Shift.EmptyStatement, {}, f);

export const fuzzExport = f =>
  ap(Shift.Export, {"declaration": choose(fuzzClassDeclaration, fuzzFunctionDeclaration, fuzzVariableDeclaration)}, f);

export const fuzzExportAllFrom = f =>
  ap(Shift.ExportAllFrom, {"moduleSpecifier": fuzzString}, f);

export const fuzzExportDefault = f =>
  ap(Shift.ExportDefault, {"body": choose(fuzzClassDeclaration, f => fuzzExpression(f), fuzzFunctionDeclaration)}, f);

export const fuzzExportFrom = f =>
  ap(Shift.ExportFrom, {"namedExports": many(fuzzExportFromSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzExportFromSpecifier = f =>
  ap(Shift.ExportFromSpecifier, {"name": fuzzString, "exportedName": opt(fuzzString)}, f);

export const fuzzExportLocalSpecifier = f =>
  ap(Shift.ExportLocalSpecifier, {"name": fuzzIdentifierExpression, "exportedName": opt(fuzzString)}, f);

export const fuzzExportLocals = f =>
  ap(Shift.ExportLocals, {"namedExports": many(fuzzExportLocalSpecifier)}, f);

export const fuzzExpressionStatement = f =>
  ap(Shift.ExpressionStatement, {"expression": f => fuzzExpression(f)}, f);

export const fuzzForInStatement = f =>
  ap(Shift.ForInStatement, {"left": choose(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), fuzzVariableDeclaration), "right": f => fuzzExpression(f), "body": f => fuzzStatement(f)}, f);

export const fuzzForOfStatement = f =>
  ap(Shift.ForOfStatement, {"left": choose(choose(choose(fuzzArrayAssignmentTarget, fuzzObjectAssignmentTarget), choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))), fuzzVariableDeclaration), "right": f => fuzzExpression(f), "body": f => fuzzStatement(f)}, f);

export const fuzzForStatement = f =>
  ap(Shift.ForStatement, {"init": opt(choose(f => fuzzExpression(f), fuzzVariableDeclaration)), "test": opt(f => fuzzExpression(f)), "update": opt(f => fuzzExpression(f)), "body": f => fuzzStatement(f)}, f);

export const fuzzFormalParameters = f =>
  ap(Shift.FormalParameters, {"items": many(choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))), "rest": opt(choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)))}, f);

export const fuzzFunctionBody = f =>
  ap(Shift.FunctionBody, {"directives": many(fuzzDirective), "statements": many(f => fuzzStatement(f))}, f);

export const fuzzFunctionDeclaration = f =>
  ap(Shift.FunctionDeclaration, {"isGenerator": f => f.rng.nextBoolean(), "name": fuzzBindingIdentifier, "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzFunctionExpression = f =>
  ap(Shift.FunctionExpression, {"isGenerator": f => f.rng.nextBoolean(), "name": opt(fuzzBindingIdentifier), "params": fuzzFormalParameters, "body": fuzzFunctionBody}, f);

export const fuzzGetter = f =>
  ap(Shift.Getter, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "body": fuzzFunctionBody}, f);

export const fuzzIdentifierExpression = f =>
  ap(Shift.IdentifierExpression, {"name": fuzzString}, f);

export const fuzzIfStatement = f =>
  ap(Shift.IfStatement, {"test": f => fuzzExpression(f), "consequent": f => fuzzStatement(f), "alternate": opt(f => fuzzStatement(f))}, f);

export const fuzzImport = f =>
  ap(Shift.Import, {"defaultBinding": opt(fuzzBindingIdentifier), "namedImports": many(fuzzImportSpecifier), "moduleSpecifier": fuzzString}, f);

export const fuzzImportNamespace = f =>
  ap(Shift.ImportNamespace, {"defaultBinding": opt(fuzzBindingIdentifier), "namespaceBinding": fuzzBindingIdentifier, "moduleSpecifier": fuzzString}, f);

export const fuzzImportSpecifier = f =>
  ap(Shift.ImportSpecifier, {"name": opt(fuzzString), "binding": fuzzBindingIdentifier}, f);

export const fuzzLabeledStatement = f =>
  ap(Shift.LabeledStatement, {"label": fuzzString, "body": f => fuzzStatement(f)}, f);

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
  ap(Shift.Module, {"directives": many(fuzzDirective), "items": many(choose(choose(fuzzExport, fuzzExportAllFrom, fuzzExportDefault, fuzzExportFrom, fuzzExportLocals), choose(fuzzImport, fuzzImportNamespace), f => fuzzStatement(f)))}, f);

export const fuzzNewExpression = f =>
  ap(Shift.NewExpression, {"callee": f => fuzzExpression(f), "arguments": many(choose(f => fuzzExpression(f), fuzzSpreadElement))}, f);

export const fuzzNewTargetExpression = f =>
  ap(Shift.NewTargetExpression, {}, f);

export const fuzzObjectAssignmentTarget = f =>
  ap(Shift.ObjectAssignmentTarget, {"properties": many(choose(fuzzAssignmentTargetPropertyIdentifier, fuzzAssignmentTargetPropertyProperty))}, f);

export const fuzzObjectBinding = f =>
  ap(Shift.ObjectBinding, {"properties": many(choose(fuzzBindingPropertyIdentifier, fuzzBindingPropertyProperty))}, f);

export const fuzzObjectExpression = f =>
  ap(Shift.ObjectExpression, {"properties": many(choose(choose(fuzzDataProperty, choose(fuzzGetter, fuzzMethod, fuzzSetter)), fuzzShorthandProperty))}, f);

export const fuzzReturnStatement = f =>
  ap(Shift.ReturnStatement, {"expression": opt(f => fuzzExpression(f))}, f);

export const fuzzScript = f =>
  ap(Shift.Script, {"directives": many(fuzzDirective), "statements": many(f => fuzzStatement(f))}, f);

export const fuzzSetter = f =>
  ap(Shift.Setter, {"name": choose(fuzzComputedPropertyName, fuzzStaticPropertyName), "param": choose(fuzzBindingWithDefault, choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding))), "body": fuzzFunctionBody}, f);

export const fuzzShorthandProperty = f =>
  ap(Shift.ShorthandProperty, {"name": fuzzIdentifierExpression}, f);

export const fuzzSpreadElement = f =>
  ap(Shift.SpreadElement, {"expression": f => fuzzExpression(f)}, f);

export const fuzzStaticMemberAssignmentTarget = f =>
  ap(Shift.StaticMemberAssignmentTarget, {"object": choose(f => fuzzExpression(f), fuzzSuper), "property": fuzzString}, f);

export const fuzzStaticMemberExpression = f =>
  ap(Shift.StaticMemberExpression, {"object": choose(f => fuzzExpression(f), fuzzSuper), "property": fuzzString}, f);

export const fuzzStaticPropertyName = f =>
  ap(Shift.StaticPropertyName, {"value": fuzzString}, f);

export const fuzzSuper = f =>
  ap(Shift.Super, {}, f);

export const fuzzSwitchCase = f =>
  ap(Shift.SwitchCase, {"test": f => fuzzExpression(f), "consequent": many(f => fuzzStatement(f))}, f);

export const fuzzSwitchDefault = f =>
  ap(Shift.SwitchDefault, {"consequent": many(f => fuzzStatement(f))}, f);

export const fuzzSwitchStatement = f =>
  ap(Shift.SwitchStatement, {"discriminant": f => fuzzExpression(f), "cases": many(fuzzSwitchCase)}, f);

export const fuzzSwitchStatementWithDefault = f =>
  ap(Shift.SwitchStatementWithDefault, {"discriminant": f => fuzzExpression(f), "preDefaultCases": many(fuzzSwitchCase), "defaultCase": fuzzSwitchDefault, "postDefaultCases": many(fuzzSwitchCase)}, f);

export const fuzzTemplateElement = f =>
  ap(Shift.TemplateElement, {"rawValue": fuzzString}, f);

export const fuzzTemplateExpression = f =>
  ap(Shift.TemplateExpression, {"tag": opt(f => fuzzExpression(f)), "elements": many(choose(f => fuzzExpression(f), fuzzTemplateElement))}, f);

export const fuzzThisExpression = f =>
  ap(Shift.ThisExpression, {}, f);

export const fuzzThrowStatement = f =>
  ap(Shift.ThrowStatement, {"expression": f => fuzzExpression(f)}, f);

export const fuzzTryCatchStatement = f =>
  ap(Shift.TryCatchStatement, {"body": fuzzBlock, "catchClause": fuzzCatchClause}, f);

export const fuzzTryFinallyStatement = f =>
  ap(Shift.TryFinallyStatement, {"body": fuzzBlock, "catchClause": opt(fuzzCatchClause), "finalizer": fuzzBlock}, f);

export const fuzzUnaryExpression = f =>
  ap(Shift.UnaryExpression, {"operator": oneOf("+", "-", "!", "~", "typeof", "void", "delete"), "operand": f => fuzzExpression(f)}, f);

export const fuzzUpdateExpression = f =>
  ap(Shift.UpdateExpression, {"isPrefix": f => f.rng.nextBoolean(), "operator": oneOf("++", "--"), "operand": choose(fuzzAssignmentTargetIdentifier, choose(fuzzComputedMemberAssignmentTarget, fuzzStaticMemberAssignmentTarget))}, f);

export const fuzzVariableDeclaration = f =>
  ap(Shift.VariableDeclaration, {"kind": oneOf("var", "let", "const"), "declarators": many(fuzzVariableDeclarator)}, f);

export const fuzzVariableDeclarationStatement = f =>
  ap(Shift.VariableDeclarationStatement, {"declaration": fuzzVariableDeclaration}, f);

export const fuzzVariableDeclarator = f =>
  ap(Shift.VariableDeclarator, {"binding": choose(fuzzBindingIdentifier, choose(fuzzArrayBinding, fuzzObjectBinding)), "init": opt(f => fuzzExpression(f))}, f);

export const fuzzWhileStatement = f =>
  ap(Shift.WhileStatement, {"test": f => fuzzExpression(f), "body": f => fuzzStatement(f)}, f);

export const fuzzWithStatement = f =>
  ap(Shift.WithStatement, {"object": f => fuzzExpression(f), "body": f => fuzzStatement(f)}, f);

export const fuzzYieldExpression = f =>
  ap(Shift.YieldExpression, {"expression": opt(f => fuzzExpression(f))}, f);

export const fuzzYieldGeneratorExpression = f =>
  ap(Shift.YieldGeneratorExpression, {"expression": f => fuzzExpression(f)}, f);

