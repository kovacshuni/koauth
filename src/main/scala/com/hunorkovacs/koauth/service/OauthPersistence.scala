package com.hunorkovacs.koauth.service

import scala.concurrent.{ExecutionContext, Future}

trait OauthPersistence {

  /**
   * Saved nonces can be deleted after a predefined time passes. Preferably longer or equal
   * to the amount the timestamp verification is tuned to.
   *
   * @return true if the nonce already exists for the given Consumer Key and Token
   */
  def nonceExists(nonce: String,
                  consumerKey: String,
                  token: String)
                 (implicit ec: ExecutionContext): Future[Boolean]

  /**
   * Save a Request Token without with void verifier username and verifier key.
   */
  def persistRequestToken(consumerKey: String,
                          requestToken: String,
                          requestTokenSecret: String,
                          callback: String)
                         (implicit ec: ExecutionContext): Future[Unit]

  /**
   * @return Consumer Secret associated to given Consumer Key
   */
  def getConsumerSecret(consumerKey: String)
                       (implicit ec: ExecutionContext): Future[Option[String]]

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

  /**
   * Simple authentication using directly username and password.
   *
   * @return true if this user exists with the respective password, false otherwise
   */
  def authenticate(username: String, password: String)
                  (implicit ec: ExecutionContext): Future[Boolean]

  /**
   * @return The associated username to the token in a Some, otherwise a None.
   */
  def whoAuthorizedRequesToken(consumerKey: String,
                               requestToken: String,
                               verifier: String)
                              (implicit ec: ExecutionContext): Future[Option[String]]

  /**
   * Saves an Access Token with companion attributes.
   */
  def persistAccessToken(consumerKey: String,
                         accessToken: String,
                         accessTokenSecret: String,
                         username: String)
                        (implicit ec: ExecutionContext): Future[Unit]

  /**
   * @return the Token Secret in a Some. If not found, a None
   */
  def getTokenSecret(consumerKey: String, accessToken: String)
                    (implicit ec: ExecutionContext): Future[Option[String]]

  /**
   * @return the username associated to the token
   */
  def getUsername(consumerKey: String, accessToken: String)
                 (implicit ec: ExecutionContext): Future[String]
}
