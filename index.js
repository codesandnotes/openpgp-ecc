var alice = {
    userId: {
        name: 'alice',
        email: 'alice@can.do'
    },
    passphrase: 'alice passphrase',
    keys: {
        publicArmored: undefined,
        privateArmored: undefined
    }
};

var bob = {
    userId: {
        name: 'bob',
        email: 'bob@can.do'
    },
    passphrase: 'bob passphrase',
    keys: {
        publicArmored: undefined,
        privateArmored: undefined
    }
};

openpgp.generateKey({
    userIds: alice.userId,
    curve: "ed25519",
    passphrase: alice.passphrase
}).then(function (key) {
    alice.keys.publicArmored = key.publicKeyArmored;
    alice.keys.privateArmored = key.privateKeyArmored;
    $('#alice-com').text("Alice's keys generated");
});

openpgp.generateKey({
    userIds: bob.userId,
    curve: "ed25519",
    passphrase: bob.passphrase
}).then(function (key) {
    bob.keys.publicArmored = key.publicKeyArmored;
    bob.keys.privateArmored = key.privateKeyArmored;
    $('#bob-com').text("Bob's keys generated");
});

$().ready(function () {

    var encrypt = function (sender, message, receiver) {
        var senderPrivateKeys, receiverPublicKeys;

        return new Promise(function (resolve) {
            openpgp.key.readArmored(sender.keys.privateArmored).then(function (readKeys) {
                senderPrivateKeys = readKeys;

                return senderPrivateKeys.keys[0].decrypt(sender.passphrase);
            }).then(function () {

                return openpgp.key.readArmored(receiver.keys.publicArmored);
            }).then(function (readKeys) {
                receiverPublicKeys = readKeys;

                return openpgp.encrypt({
                    armor: true,
                    compression: openpgp.enums.compression.zlib,
                    message: openpgp.message.fromText(message),
                    publicKeys: receiverPublicKeys.keys,
                    privateKeys: senderPrivateKeys.keys
                });
            }).then(function (encrypted) {

                resolve(encrypted.data);
            });
        });
    };

    var decrypt = function (receiver, encryptedArmoredMessage, sender) {
        var receiverPrivateKeys, senderPublicKeys;

        return new Promise(function (resolve) {
            openpgp.key.readArmored(receiver.keys.privateArmored).then(function (readKeys) {
                receiverPrivateKeys = readKeys;

                return receiverPrivateKeys.keys[0].decrypt(receiver.passphrase);
            }).then(function () {

                return openpgp.key.readArmored(sender.keys.publicArmored);
            }).then(function (readKeys) {
                senderPublicKeys = readKeys;

                return openpgp.message.readArmored(encryptedArmoredMessage);
            }).then(function (readMessage) {

                return openpgp.decrypt({
                    message: readMessage,
                    privateKeys: receiverPrivateKeys.keys,
                    publicKeys: senderPublicKeys.keys
                });
            }).then(function (decrypted) {

                resolve(decrypted.data);
            });
        });
    };

    $('button#alice-send').on('click', function () {

        var message = $('#alice-write').val();

        encrypt(alice, message, bob).then(function (encryptedArmoredMessage) {
            $('#alice-encrypted').text(encryptedArmoredMessage);

            return decrypt(bob, encryptedArmoredMessage, alice);
        }).then(function (decryptedMessage) {

            $('#bob-read').text(decryptedMessage);
        });
    });

    $('button#bob-send').on('click', function () {

        var message = $('#bob-write').val();

        encrypt(bob, message, alice).then(function (encryptedArmoredMessage) {
            $('#bob-encrypted').text(encryptedArmoredMessage);

            return decrypt(alice, encryptedArmoredMessage, bob);
        }).then(function (decryptedMessage) {

            $('#alice-read').text(decryptedMessage);
        });
    });
});
