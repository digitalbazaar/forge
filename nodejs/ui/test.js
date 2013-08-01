var ASSERT = chai.assert;
mocha.setup({
    ui: 'bdd'
});
requirejs.config({
    paths: {
        forge: 'forge',
        test: 'test'
    }
});
requirejs([
    'test/rsa',
    'test/aes',
    'test/tls'
], function() {
    mocha.run();
});
