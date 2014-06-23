package com.hunorkovacs.koauth.service

import java.util.Date

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthParams, Rights}

trait OauthPersistence {



  def getRights(requestTokenF: Future[String])
               (implicit ec: ExecutionContext): Future[Rights]

  def authenticate(usernameF: Future[String], passwordF: Future[String])
                  (implicit ec: ExecutionContext): Future[Unit]

  def authorize(consumerKeyF: Future[String], tokenF: Future[String],
                usernameF: Future[String], verifierF: Future[String])
               (implicit ec: ExecutionContext): Future[Unit]

  def whoAuthorizedRequestToken(consumerKeyF: Future[String], tokenF: Future[String],
                               verifierF: Future[String])
                              (implicit ec: ExecutionContext): Future[(String, Rights)]

  def persistAccessToken(consumerKeyF: Future[String], consumerSecretF: Future[String],
                         tokenF: Future[String], tokenSecretF: Future[String],
                         rightsF: Future[Rights], usernameF: Future[String])
                         (implicit ec: ExecutionContext): Future[Unit]

  def getToken(consumerKeyF: Future[String], tokenF: Future[String])
                        (implicit ec: ExecutionContext): Future[(String, String, String, Rights)]

  /// new functions

  def nonceExists(nonce: String,
                  consumerKey: String,
                  token: String)
                 (implicit ec: ExecutionContext): Future[Boolean]

  def persistRequestToken(consumerKey: String,
                          requestToken: String,
                          requestTokenSecret: String,
                          callback: String)
                         (implicit ec: ExecutionContext): Future[Unit]

  def getConsumerSecret(consumerKey: String)
                       (implicit ec: ExecutionContext): Future[String]

}

case class Consumer(consumerKey: String,
                     consumerSecret: String,
                     appId: Int,
                     ownerUsername: String,
                     rights: Rights)

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
