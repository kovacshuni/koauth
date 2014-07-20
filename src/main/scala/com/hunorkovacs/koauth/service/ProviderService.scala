package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.service.DefaultVerifier.MessageNotAuthorized
import com.hunorkovacs.koauth.service.VerifierFactory.getDefaultOauthVerifier

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Generator._
import com.hunorkovacs.koauth.service.Arithmetics._
import com.hunorkovacs.koauth.domain.OauthParams._

trait ProviderService {

  def requestToken(request: Request)
                  (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse]

  def authorize(request: Request)
               (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse]

  def accessToken(request: Request)
                 (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse]

  def oauthenticate(request: Request)
                   (implicit persistenceService: Persistence, ec: ExecutionContext): Future[Either[OauthResponse, String]]
}

protected class CustomProviderService(val oauthVerifier: Verifier) extends ProviderService {

  import oauthVerifier._

  def requestToken(request: Request)
                  (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForRequestToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          callback <- Future(request.oauthParamsMap(callbackName))
          (token, secret) = generateTokenAndSecret
          persisted <- persistenceService.persistRequestToken(consumerKey, token, secret, callback)
          response <- createRequestTokenResponse(token, secret, callback)
        } yield response
    }
  }

  def authorize(request: Request)
               (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForAuthorize(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          requestToken <- Future(request.oauthParamsMap(tokenName))
          username <- Future(request.oauthParamsMap(usernameName))
          verifier = generateVerifier
          authorization <- persistenceService.authorizeRequestToken(consumerKey, requestToken, username, verifier)
          response <- createAuthorizeResponse(requestToken, verifier)
        } yield response
    }
  }

  def accessToken(request: Request)
                 (implicit persistenceService: Persistence, ec: ExecutionContext): Future[OauthResponse] = {
    verifyForAccessToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        (for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          requestToken <- Future(request.oauthParamsMap(tokenName))
          verifier <- Future(request.oauthParamsMap(verifierName))
          user <- persistenceService.whoAuthorizedRequesToken(consumerKey, requestToken, verifier)
        } yield user) flatMap {
          case None => Future(new ResponseUnauthorized(MessageNotAuthorized))
          case Some(username) =>
            for {
              consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
              (token, secret) = generateTokenAndSecret
              accessToken <- persistenceService.persistAccessToken(consumerKey, token, secret, username)
              response <- createAccesTokenResponse(token, secret)
            } yield response
        }
    }
  }

  def oauthenticate(request: Request)
                   (implicit persistenceService: Persistence, ec: ExecutionContext): Future[Either[OauthResponse, String]] = {
    verifyForOauthenticate(request) flatMap {
      case VerificationUnsupported(message) => successful(Left(new ResponseBadRequest(message)))
      case VerificationFailed(message) => successful(Left(new ResponseUnauthorized(message)))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(consumerKeyName))
          token <- Future(request.oauthParamsMap(tokenName))
          username <- persistenceService.getUsername(consumerKey, token)
        } yield Right(username)
    }
  }
}

object ProviderServiceFactory {

  def createDefaultOauthService = new CustomProviderService(getDefaultOauthVerifier)

  def createCustomOauthService(oauthVerifier: Verifier) = new CustomProviderService(oauthVerifier)
}
