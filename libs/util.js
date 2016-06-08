var Promise = require('es6-promises');

// es6-promisify looks like it was written by idiots.
exports.promisify = function(f) {
  return new Promise(function(resolve, reject){
    f(function(err, val){
      if (err) return reject(err);
      resolve(val);
    });
  });
};

// Lift fn into the Promise p
exports.liftP = function (p, fn) {
  return p.then(function(v){return fn(v);});
}
