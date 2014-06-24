package com.hunorkovacs.koauth.service

import java.util.Date

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthParams, Rights}

trait OauthPersistence {



  def getRights(requestTokenF: Future[String])
               (implicit ec: ExecutionContext): Future[Rights]

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

  /**
   * You should be able to find a RequestToken by its Consumer Key and Request Token.
   * This method should complete and persist (update) that already exisiting record with the verifying username and verifier key.
   * If the respective Request Token doesn't exist or it's already verified this should fail somehow.
   *
   * @param verifierUsername The username who is authorizing the token.
   * @param verifier The verifier key that was generated during the authorization.
   */
  def authorizeRequestToken(consumerKey: String,
                            requestToken: String,
                            verifierUsername: String,
                            verifier: String)
                           (implicit ec: ExecutionContext): Future[Unit]

  def getConsumerSecret(consumerKey: String)
                       (implicit ec: ExecutionContext): Future[String]

  def authenticate(username: String, password: String)
                  (implicit ec: ExecutionContext): Future[Boolean]
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
