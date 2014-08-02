package com.hunorkovacs.koauth.service.provider.persistence

case class Consumer(consumerKey: String,
                    consumerSecret: String,
                    ownerUsername: String)

case class RequestToken(consumerKey: String,
                        requestToken: String,
                        requestTokenSecret: String,
                        callback: String,
                        verifierUsername: Option[String],
                        verifier: Option[String])

case class AccessToken(consumerKey: String,
                       accessToken: String,
                       accessTokenSecret: String,
                       username: String)

case class Nonce(nonce: String,
                 consumerKey: String,
                 token: String)

case class User(username: String,
                password: String)
