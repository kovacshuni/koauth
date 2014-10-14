package com.hunorkovacs.koauth.service.provider.persistence

import scala.concurrent.Future

trait Persistence {

  /**
   * Saved nonces can be deleted after a predefined time passes. Preferably longer or equal
   * to the amount the timestamp verification is tuned to.
   *
   * @return true if the nonce already exists for the given Consumer Key and Token
   */
  def nonceExists(nonce: String,
                  consumerKey: String,
                  token: String): Future[Boolean]

  def persistNonce(nonce: String,
                   consumerKey: String,
                   token: String): Future[Unit]

  /**
   * Save a Request Token without with void verifier username and verifier key.
   */
  def persistRequestToken(consumerKey: String,
                          requestToken: String,
                          requestTokenSecret: String,
                          callback: String): Future[Unit]

  /**
   * @return Consumer Secret associated to given Consumer Key
   */
  def getConsumerSecret(consumerKey: String): Future[Option[String]]

  /**
   * @return The associated username to the token in a Some, otherwise a None.
   */
  def whoAuthorizedRequestToken(consumerKey: String,
                                requestToken: String,
                                verifier: String): Future[Option[String]]

  /**
   * Saves an Access Token with companion attributes.
   */
  def persistAccessToken(consumerKey: String,
                         accessToken: String,
                         accessTokenSecret: String,
                         username: String): Future[Unit]


  def getRequestTokenSecret(consumerKey: String, requestToken: String): Future[Option[String]]

  /**
   * @return the Token Secret in a Some. If not found, a None
   */
  def getAccessTokenSecret(consumerKey: String, accessToken: String): Future[Option[String]]

  /**
   * @return the username associated to the token
   */
  def getUsername(consumerKey: String, accessToken: String): Future[Option[String]]
}
