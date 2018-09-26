let local = require('../');
let regex = require('../dist/regexp.js');
let n = 0;
let bugAvoidance = regex.RegExpBugAvoidanceConfiguration.fromEngine();
while (true) {
	let expression = regex.default(new local.FuzzerState(), regex.engineSupportsRegexUnicode(), bugAvoidance);
	let flags = [
		expression.global ? 'g' : '',
		expression.ignoreCase ? 'i' : '',
		expression.multiline ? 'm' : '',
		expression.sticky ? 'y' : '',
		expression.unicode ? 'u' : ''
	].join('');
	try {
		RegExp(expression.pattern, flags);
	} catch (e) {
		console.log(`failure: /${expression.pattern}/${flags},\nerror: ${e.message}`);
	}
	n++;
	if (n % 100000 === 0) {
		console.log(`${n} done`);
	}
}
  