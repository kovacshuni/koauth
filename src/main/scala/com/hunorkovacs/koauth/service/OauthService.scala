package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.service.OauthVerifierFactory.getDefaultOauthVerifier

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.OauthExtractor._
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthRequest
import com.hunorkovacs.koauth.domain.OauthParams._

trait OauthService {

  def requestToken(request: OauthRequest)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def authorize(request: OauthRequest)
               (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def accessToken(request: OauthRequest)
                 (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def oauthenticate(request: OauthRequest)
                   (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[Either[OauthResponse, String]]
}

protected class CustomOauthService(val oauthVerifier: OauthVerifier) extends OauthService {

  import oauthVerifier._

  def requestToken(request: OauthRequest)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    val enhancedRequestF = enhanceRequest(request)
    enhancedRequestF.flatMap(r => verify(r, verifyForRequestToken)) flatMap {
      case VerificationOk =>
        for {
          (token, secret) <- generateTokenAndSecret
          consumerKey <- enhancedRequestF.map(r => r.oauthParamsMap(consumerKeyName))
          callback <- enhancedRequestF.map(r => r.oauthParamsMap(callbackName))
          persisted <- persistenceService.persistRequestToken(consumerKey, token, secret, callback)
          response <- createRequestTokenResponse(token, secret, callback)
        } yield response
      case VerificationFailed(message) => Future(new OauthResponseUnauthorized(message))
      case VerificationUnsupported(message) => Future(new OauthResponseBadRequest(message))
    }
  }

  def authorize(request: OauthRequest)
               (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    (for {
      enhancedRequest <- enhanceRequest(request)
      username = enhancedRequest.oauthParamsMap(usernameName)
      password = enhancedRequest.oauthParamsMap(passwordName)
      auth <- persistenceService.authenticate(username, password)
    } yield auth) flatMap {
      case true =>
        for {
          enhancedRequest <- enhanceRequest(request)
          consumerKey = enhancedRequest.oauthParamsMap(consumerKeyName)
          requestToken = enhancedRequest.oauthParamsMap(tokenName)
          username = enhancedRequest.oauthParamsMap(usernameName)
          verifier <- generateVerifier
          authorization <- persistenceService.authorizeRequestToken(consumerKey, requestToken, username, verifier)
          response <- createAuthorizeResponse(requestToken, verifier)
        } yield response
      case false => Future(new OauthResponseUnauthorized("Authentication credentials invalid."))
    }
  }

  def accessToken(request: OauthRequest)
                 (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    val enhancedRequestF = enhanceRequest(request)
    enhancedRequestF.flatMap(verifyWithToken) flatMap {
      case VerificationFailed(message) => Future(new OauthResponseUnauthorized(message))
      case VerificationUnsupported(message) => Future(new OauthResponseBadRequest(message))
      case VerificationOk =>
        (for {
          enhancedRequest <- enhancedRequestF
          consumerKey = enhancedRequest.oauthParamsMap(consumerKeyName)
          requestToken = enhancedRequest.oauthParamsMap(tokenName)
          user <- persistenceService.whoAuthorizedRequesToken(consumerKey, requestToken)
        } yield user) flatMap {
          case None => Future(new OauthResponseUnauthorized("Request Token not authorized"))
          case Some(username) =>
            for {
              enhancedRequest <- enhanceRequest(request)
              consumerKey = enhancedRequest.oauthParamsMap(consumerKeyName)
              (token, secret) <- generateTokenAndSecret
              accessToken <- persistenceService.persistAccessToken(consumerKey, token, secret, username)
              response <- createAccesTokenResponse(token, secret)
            } yield response
        }
    }
  }

  def oauthenticate(request: OauthRequest)
                   (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[Either[OauthResponse, String]] = {
    val enhancedRequestF = enhanceRequest(request)
    (for {
      enhancedRequest <- enhancedRequestF
      verification <- verifyWithToken(enhancedRequest)
    } yield verification) flatMap {
      case VerificationUnsupported(message) => Future(Left(new OauthResponseBadRequest(message)))
      case VerificationFailed(message) => Future(Left(new OauthResponseUnauthorized(message)))
      case VerificationOk =>
        for {
          consumerKey <- enhancedRequestF.map(r => r.oauthParamsMap(consumerKeyName))
          token <- enhancedRequestF.map(r => r.oauthParamsMap(tokenName))
          username <- persistenceService.getUsername(consumerKey, token)
        } yield Right(username)
    }
  }
}

object OauthServiceFactory {

  def createDefaultOauthService = new CustomOauthService(getDefaultOauthVerifier)

  def createCustomOauthService(oauthVerifier: OauthVerifier) = new CustomOauthService(oauthVerifier)
}
