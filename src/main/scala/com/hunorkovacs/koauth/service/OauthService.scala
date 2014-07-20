package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.service.DefaultOauthVerifier.MessageNotAuthorized
import com.hunorkovacs.koauth.service.OauthVerifierFactory.getDefaultOauthVerifier

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams._

trait OauthService {

  def requestToken(request: Request)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def authorize(request: Request)
               (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def accessToken(request: Request)
                 (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse]

  def oauthenticate(request: Request)
                   (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[Either[OauthResponse, String]]
}

protected class CustomOauthService(val oauthVerifier: OauthVerifier) extends OauthService {

  import oauthVerifier._

  def requestToken(request: Request)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForRequestToken(request) flatMap {
      case VerificationFailed(message) => successful(new OauthResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new OauthResponseBadRequest(message))
      case VerificationOk =>
        for {
          (token, secret) <- generateTokenAndSecret
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          callback <- Future(request.oauthParamsMap(callbackName))
          persisted <- persistenceService.persistRequestToken(consumerKey, token, secret, callback)
          response <- createRequestTokenResponse(token, secret, callback)
        } yield response
    }
  }

  def authorize(request: Request)
               (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForAuthorize(request) flatMap {
      case VerificationFailed(message) => successful(new OauthResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new OauthResponseBadRequest(message))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          requestToken <- Future(request.oauthParamsMap(tokenName))
          username <- Future(request.oauthParamsMap(usernameName))
          verifier <- generateVerifier
          authorization <- persistenceService.authorizeRequestToken(consumerKey, requestToken, username, verifier)
          response <- createAuthorizeResponse(requestToken, verifier)
        } yield response
    }
  }

  def accessToken(request: Request)
                 (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForAccessToken(request) flatMap {
      case VerificationFailed(message) => successful(new OauthResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new OauthResponseBadRequest(message))
      case VerificationOk =>
        (for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          requestToken <- Future(request.oauthParamsMap(tokenName))
          verifier <- Future(request.oauthParamsMap(verifierName))
          user <- persistenceService.whoAuthorizedRequesToken(consumerKey, requestToken, verifier)
        } yield user) flatMap {
          case None => Future(new OauthResponseUnauthorized(MessageNotAuthorized))
          case Some(username) =>
            for {
              consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
              (token, secret) <- generateTokenAndSecret
              accessToken <- persistenceService.persistAccessToken(consumerKey, token, secret, username)
              response <- createAccesTokenResponse(token, secret)
            } yield response
        }
    }
  }

  def oauthenticate(request: Request)
                   (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[Either[OauthResponse, String]] = {
    verifyForOauthenticate(request) flatMap {
      case VerificationUnsupported(message) => successful(Left(new OauthResponseBadRequest(message)))
      case VerificationFailed(message) => successful(Left(new OauthResponseUnauthorized(message)))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          token <- Future(request.oauthParamsMap(tokenName))
          username <- persistenceService.getUsername(consumerKey, token)
        } yield Right(username)
    }
  }
}

object OauthServiceFactory {

  def createDefaultOauthService = new CustomOauthService(getDefaultOauthVerifier)

  def createCustomOauthService(oauthVerifier: OauthVerifier) = new CustomOauthService(oauthVerifier)
}
