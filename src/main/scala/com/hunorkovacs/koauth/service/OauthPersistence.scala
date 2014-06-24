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

  def authenticate(username: String, password: String)
                  (implicit ec: ExecutionContext): Future[Boolean]

  /**
   * 
   * @param consumerKey
   * @param requestToken
   * @return The associated username to the token in a Some, otherwise a None.
   */
  def whoAuthorizedRequesToken(consumerKey: String,
                               requestToken: String)
                              (implicit ec: ExecutionContext): Future[Option[String]]

  def persistAccessToken(consumerKey: String,
                         accessToken: String,
                         accessTokenSecret: String,
                         username: String)
                        (implicit ec: ExecutionContext): Future[Unit]
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
