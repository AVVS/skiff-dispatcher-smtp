'use strict';

/**
 * As the system is distributed, we must treat it as such. Because we need to scale
 * linearly, we need to use all the nodes that are in the cluster. Therefore the following
 * approach is proposed: when leader receives request to get a specific resource,
 * it determines whether we already have it in the cache, and if we do, redirects the call
 * to a given node and performs operation there. Otherwise it opens connection on the node,
 * which received the request initially, pushes node id into the state, so that subsequent
 * calls are going through it, and instantiates a timer, which will destroy connection on
 * it's expiration. Furthermore, we must instantiate event listener on the other nodes, that
 * will cleanup cached resources in the event that a worker dies
 */

// this will be installed in a top-level module
var Dispatcher = require('skiff-dispatcher');
var _oauthCredentials = {};
var _ = require('lodash');
var nodemailer = require('nodemailer');
var smtpPool = require('nodemailer-smtp-pool');
var xoauth2 = require('xoauth2');
var wellknown = require('nodemailer-wellknown');
var LRU = require('lru-cache');

var connectionCache = LRU({
    // keep no more than 1k connections opened at the same time on this node
    max: 1000,
    dispose: function (key, connection) {
        connection.it.close();
        connection.cluster.set(connection.key, null);
    }
});

var credentialsCache = LRU({
    max: 10000,
    dispose: function (key, credentials) {
        credentials.cluster.set(credentials.key, null);
    }
});

/**
 * Returns node id, where smtp connection had been established.
 *
 * This is not supposed to be proxied through getsetnx - it's an independent call
 *
 * @param {String}   username
 * @param {Object}   credentials { password, provider, refreshToken }
 * @param {Boolean}  force - will be set to true if this node must establish connection even
 *                         	 if it is not a leader
 * @param {Function} next
 */
exports.getSMTPConnection = function (username, credentials, force, next) {
    var callback;
    var cluster = this.gossip.cluster;
    var currentLeader = cluster.get('leader');
    var operationKey = this.ok('getSMTPConnection', username);

    function connectionCallback(err, nodeId) {
        if (err) {
            return callback(err);
        }

        cluster.set(operationKey, nodeId);
        return callback(null, nodeId);
    }

    if (force) {
        callback = this.callbackQueue.add(operationKey, next);
        if (!callback) {
            return;
        }

        return this.establishSMTPConnection(username, credentials, connectionCallback);
    }

    if (currentLeader !== this.id) {
        return this._remoteCall(currentLeader, 'getSMTPConnection', [ username, credentials, false ], next);
    }

    var smtpNodeId = cluster.get(operationKey);
    if (smtpNodeId && this.peerOnline(smtpNodeId)) {
        return next(null, smtpNodeId);
    } else if (smtpNodeId === this.id) {
        return this.establishSMTPConnection(username, credentials, next);
    }

    // now establish a single callback
    callback = this.callbackQueue.add(operationKey, next);

    var peerNode = this.randomPeerOrSelf();
    if (peerNode !== this) {
        return this._remoteCall(peerNode.id, 'establishSMTPConnection', [ username, credentials, true ], connectionCallback);
    }

    this.establishSMTPConnection(username, credentials, connectionCallback);
};

/**
 * Establishes smtp connection for a given user
 * @param {String}   username
 * @param {Object}   credentials
 * @param {Function} next
 */
exports.establishSMTPConnection = function (username, credentials, next) {

    var operationKey = this.ok('establishSMTPConnection', username);
    var callback = this.callbackQueue.add(operationKey, next);
    if (!callback) {
        return;
    }

    var connection = connectionCache.get(username);
    if (!connection) {
        connection = nodemailer.createTransport(smtpPool(_.extend(wellknown(credentials.provider), {
            maxConnections: 2,
            maxMessages: 100
        })));

        connectionCache.set(username, {
            it: connection,
            cluster: this.gossip.cluster,
            key: this.ok('getSMTPConnection', username)
        });
    }

    this.getSMTPCredentials(username, credentials, function receivedCredentials(err, authenticationOptions) {
        if (err) {
            return callback(err);
        }

        // update them, as oauth token could've expired
        connection.auth = authenticationOptions;
        callback(null, this.id);
    });
};

/**
 * Send mail using established transport
 * @param {String}   username - from whom we are sending email
 * @param {Object}   options:
 *    @param {Object} credentials - nodemail auth object format
 *    @param {Object} email - nodemail email options
 *    @param [String] prepareEmailFunctionName - preprocess email options on the
 *                                               node that will be sending the email
 * @param {Function} next
 */
exports.sendMail = function (username, options, next) {
    var self = this;
    this.getSMTPConnection(username, options.credentials, function getSMTPConnectionNodeId(err, nodeId) {
        if (err) {
            return next(err);
        }

        if (self.id !== nodeId) {
            return self._remoteCall(nodeId, 'sendMail', [ username, options ], next);
        }

        var connection = connectionCache.get(username);
        var prepareEmailFunctionName = options.prepareEmailFunctionName;
        var email = options.email;
        if (!prepareEmailFunctionName || typeof self[prepareEmailFunctionName] !== 'function') {
            return connection.sendMail(email, next);
        }

        self[prepareEmailFunctionName](username, email, function sendPreparedEmail(err, email) {
            if (err) {
                return next(err);
            }

            connection.sendMail(email, next);
        });

    });
};

/**
 * Generates gmail credentials
 *
 * @param {String}   username
 * @param {Object}   credentials
 * @param {Function} next
 */
exports.generateOAuthCredentials = function (username, credentials, next) {
    var operationKey = this.ok('generateOAuthCredentials', username);
    var callback = this.callbackQueue.add(operationKey, next);
    if (!callback) {
        return;
    }

    var provider = credentials.provider;
    var xoauth2Instance = credentialsCache.get(username);
    if (!xoauth2Instance) {
        xoauth2Instance = xoauth2.createXOAuth2Generator(_.extend({
            user: username,
            refreshToken: credentials.refreshToken
        }, _oauthCredentials[provider]));

        credentialsCache.set(username, {
            it: xoauth2Instance,
            cluster: this.gossip.cluster,
            key: operationKey
        });
    } else {
        xoauth2Instance = xoauth2Instance.it;
    }

    this.gossip.cluster.set(operationKey, this.id);

    if (xoauth2Instance.token && (!xoauth2Instance.timer || xoauth2Instance.timer > Date.now() - 1000 * 60 * 5)) {
        return callback(null, { user: username, xoauth2: xoauth2Instance.token });
    }

    xoauth2Instance.generateToken(function regenerateOAuthToken(err, token) {
        if (err) {
            return callback(err);
        }

        return callback(null, { user: username, xoauth2: token });
    });
};

/**
 * Generates set of credentials for email providers
 *
 * TODO: make providers configurable
 *
 * @param {String}   username
 * @param {Object}   credentials
 * @param {Function} next
 */
exports.getSMTPCredentials = function (username, credentials, next) {
    var cluster = this.gossip.cluster;
    var provider = credentials.provider;

    switch (provider) {
        case 'gmail':
            var xoauth2Instance = credentialsCache.get(username);
            if (xoauth2Instance) {
                return this.generateGmailCredentials(username, credentials, next);
            }

            // find if we already have a node with the key
            var oauthCredentialsKey = this.ok('generateOAuthCredentials', username);
            var credentialsNodeId = cluster.get(oauthCredentialsKey);
            if (credentialsNodeId && this.peerOnline(credentialsNodeId)) {
                return this._remoteCall(credentialsNodeId, 'generateOAuthCredentials', [ username, credentials ], next);
            }

            var currentLeader = cluster.get('leader');
            if (currentLeader !== this.id) {
                return this._remoteCall(currentLeader, 'getSMTPCredentials', [ username, credentials ], next);
            }

            // this object doesn't exist anywhere, create it
            var operationKey = this.ok('getSMTPCredentials', username);
            var callback = this.callbackQueue.add(operationKey, next);
            var peerNode = this.randomPeerOrSelf();
            if (peerNode !== this) {
                return this._remoteCall(peerNode.id, 'generateOAuthCredentials', [ username, credentials ], callback);
            }

            return this.generateGmailCredentials(username, credentials, callback);

        case 'yahoo':
        case 'aol':
            return setImmediate(next, _.pick(credentials, ['user', 'pass']));

        default:
            return setImmediate(next, new Error('passed provider is not supported'));
    }

};

/**
 * Initializes plugin
 * @param {Object} oauthCredentials
 */
exports.init = function (oauthCredentials) {
    // this must be an object in the format of { 'service': { clientId, clientSecret } }
    _oauthCredentials = oauthCredentials;

    Dispatcher.attachRemoteCall('getSMTPConnection', exports.getSMTPConnection);
    Dispatcher.attachRemoteCall('establishSMTPConnection', exports.establishSMTPConnection);
    Dispatcher.attachRemoteCall('getSMTPCredentials', exports.getSMTPCredentials);
    Dispatcher.attachRemoteCall('generateOAuthCredentials', exports.generateGmailCredentials);
    Dispatcher.attachRemoteCall('sendMail', exports.sendMail);
};
