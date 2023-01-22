module.exports = {
  root: true,
  env: {
    browser: true,
    commonjs: true,
    node: true
  },
  extends: [
    'digitalbazaar'
  ],
  parserOptions: {
    ecmaVersion: 5,
    sourceType: 'script'
  },
  rules: {
    // overrides to support ES5, remove when updated to ES20xx
    'no-unused-vars': 'warn',
    'no-var': 'off',
    'object-shorthand': 'off',
    'prefer-const': 'off',
    // fix when code is globally reformatted
    'max-len': 'off'
  }
};
