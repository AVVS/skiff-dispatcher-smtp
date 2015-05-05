# Skiff dispatcher SMTP

Plugin for skiff-dispatcher, adds methods for handling distributed email messaging

## Install

`npm install skiff-dispatcher skiff-dispatcher-smtp -S`

## Usage

```js
var Dispatcher = require('skiff-dispatcher');
var DispatcherSMTP = require('skiff-dispatcher-smtp');

DispatcherSMTP.init({
    gmail: {
        clientId: '<your client id>',
        clientSecret: '<your client secret>',
        accessUrl: '<optional>'
    },
    yahoo: {
        // ...
    }
});

// create dispatcher cluster
var dispatcher = new Dispatcher(...);

// defined this on the dispatcher object, since it can not be called remotely
dispatcher.function_to_preprocess_emails = function (username, email, next) {
    // do async preprocessing here
    // next(err, processedEmail)
};

// call the method
dispatcher.sendMail('v@aminev.me', {
    credentials: {
        // ...
    },
    email {
        // nodemailer email options
    },
    prepareEmailFunctionName: 'function_to_preprocess_emails'
}, function (err, info) {
    // ...
});

```
