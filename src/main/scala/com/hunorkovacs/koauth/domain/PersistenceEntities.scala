package com.hunorkovacs.koauth.domain

import java.util.Date

case class Consumer(consumerKey: String,
                    consumerSecret: String,
                    appId: Int,
                    ownerUsername: String)
//                    rights: Rights)

case class RequesToken(consumerKey: String,
                       requestToken: String,
                       requestTokenSecret: String,
                       callback: String,
                       verifierUsername: String,
                       verifier: String)

case class AccessToken(consumerKey: String,
                       accessToken: String,
                       accessTokenSecret: String,
                       username: String)

case class Nonce(nonce: String,
                 time: Date,
                 consumerKey: String,
                 token: String)
