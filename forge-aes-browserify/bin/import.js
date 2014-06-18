'use strict';

var fs = require('fs'),
    esp = require('esprima'),
    path = require('path'),
    _ = require('lodash'),
    escodegen = require('escodegen');

var SOURCE = process.argv[2],
    TARGET = process.argv[3];

var MODULE_NAME = path.basename(TARGET).replace(path.extname(TARGET), '');


function _mkRequire(name) {
    return {
        type: 'CallExpression',
        callee: {
            type: 'Identifier',
            name: 'require'
        },
        arguments: [{
            type: 'Literal',
            value: './' + name,
            raw: '\'./' + name + '\''
        }]
    };
}

function _mkVar(obj, name, right) {
    obj.type = 'VariableDeclaration';
    obj.kind = 'var';
    obj.declarations = [{
        type: 'VariableDeclarator',
        id: {
            type: 'Identifier',
            name: name
        },
        init: right
    }];
}

function _mkModuleExports(value) {
    value.object.name = 'module';
    value.property.name = 'exports';
}

function _transform(obj, moduleName) {
    _.each(obj, function(value, key) {
        if (typeof value !== 'object' || !value) return;

        /**
         * 1. First check assignment expressions.
         *
         * 1.1 if the left side is something like "forge.{something}"
         * this becomes var {something} = right side
         *
         * 1.2 if the left side is something like "forge.{first}.{second}"
         * this becomes something like {first}.{second} = right side
         * additionally, any {first} that matches the moduleName becomes simply module.exports
         *
         */
        if (value.type == 'AssignmentExpression') {

            if (value.left.type == 'MemberExpression' && value.left.object.name == 'forge') {
                if (value.left.property.name !== moduleName) {
                    _mkVar(obj, value.left.property.name, value.right);
                    _transform(value.right, moduleName);
                    return;
                }
            }

            if (value.left.type == 'MemberExpression' && value.left.object.object && value.left.object.object.name == 'forge') {
                var name = value.left.object.property.name;

                value.left.object = {
                    type: 'Identifier',
                    name: name == moduleName ? 'module.exports' : name
                };

                _transform(value, moduleName);
                return;
            }
        }

        /**
         * 2. This is not an assignment, if it's not an MemberExpression of forge.{something},
         *
         * simply walk it's elements and return.
         */
        if (value.type !== 'MemberExpression' || (value.object && value.object.name !== 'forge'))
            return _transform(value, moduleName);

        /**
         * 3. This must be a MemberExpression. Check if we're trying to get an object property
         *
         * This catches everythign that looks like forge.{something} and converts this
         * into a require({something}), or module.exports if it's forge.{moduleName}
         */
        if (value.property.type === 'Identifier') {
            if (key == 'left' || key == 'object') {
                if (value.property.name == moduleName)
                    return _mkModuleExports(value);
            }

            obj[key] = _mkRequire(value.property.name);
        }
    });
}

/**
 * Find a node matching the "query" and return it as soon as possible.
 */
function search(query, obj, found) {
    var keys = _.keys(obj);

    for (var i = 0; i < keys.length; i++) {
        var value = obj[keys[i]];

        if (typeof value !== 'object' || !value) continue;

        if (value.type === query.type && value.id && value.id.name === query.name) {
            return obj;
        }

        found = search(query, value, found);

        if (found) return found;
    }

    return found;
}

function _getAst(source, moduleName) {
    var src = fs.readFileSync(source);

    // hacky fix: remove references to forge.disableNativeCode
    src = src.toString().replace(/[!]?forge.disableNativeCode\s(&&|\|\|)/, '');

    // another pre-processing hack
    if (moduleName == 'pbkdf2') {
        src = src.replace('var pkcs5 = forge.pkcs5 = forge.pkcs5 || {};', 'var pkcs5 = {}');
    }

    return esp.parse(src, {
        comment: true
    });
}

function run(ast, moduleName, target) {
    var code, body, query = {
        type: 'FunctionDeclaration',
        name: 'initModule'
    };

    /**
     * First, find the function initModule. We'll only use the body of this function.
     */
    var initModule = search(query, ast);

    if( ! initModule ) return console.log('NO initModule found, cannot transform %s', moduleName );

    body = initModule[0].body;

    // Force the body type to program
    // so escodegen considers this a top-level code block
    body.type = 'Program';

    // _transform changes the AST IN PLACE
    _transform(body, moduleName);

    code = escodegen.generate(body);

    /**
     * cipher.modes is missing due a missing module.export in cipherModes
     * and a missing export in cipher
     */
    if (moduleName === 'cipher') {
        code = code + '\nmodule.exports.modes = require(\'./cipherModes\')';
    }
    if (moduleName === 'cipherModes') {
        code = code + '\nmodule.exports = modes;';
    }

    // first comment block is the copyright block
    // adding it back in.
    code = '/' + ast.comments[0].value + '*/\n' + code;

    fs.writeFileSync(target, code);
}

run(_getAst(SOURCE, MODULE_NAME), MODULE_NAME, TARGET);
