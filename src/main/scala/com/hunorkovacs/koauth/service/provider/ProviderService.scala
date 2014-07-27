package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics._
import DefaultVerifier.MessageNotAuthorized
import com.hunorkovacs.koauth.service.Generator._
import VerifierFactory.getDefaultOauthVerifier

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

trait ProviderService {

  def requestToken(request: KoauthRequest)
                  (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse]

  def authorize(request: KoauthRequest)
               (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse]

  def accessToken(request: KoauthRequest)
                 (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse]

  def oauthenticate(request: KoauthRequest)
                   (implicit persistenceService: Persistence, ec: ExecutionContext): Future[Either[KoauthResponse, String]]
}

protected class CustomProviderService(val oauthVerifier: Verifier) extends ProviderService {

  import oauthVerifier._

  def requestToken(request: KoauthRequest)
                  (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse] = {
    verifyForRequestToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val callback = request.oauthParamsMap(CallbackName)
        val nonce = request.oauthParamsMap(NonceName)
        val (token, secret) = generateTokenAndSecret
        persistenceService.persistNonce(nonce, consumerKey, token) flatMap { u =>
          persistenceService.persistRequestToken(consumerKey, token, secret, callback)
        } map { u =>
          createRequestTokenResponse(token, secret, callback)
        }
    }
  }

  def authorize(request: KoauthRequest)
               (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse] = {
    verifyForAuthorize(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val requestToken = request.oauthParamsMap(TokenName)
        val username = request.oauthParamsMap(UsernameName)
        val verifier = generateVerifier
        persistenceService.authorizeRequestToken(consumerKey, requestToken, username, verifier) map { u =>
            createAuthorizeResponse(requestToken, verifier)
        }
    }
  }

  def accessToken(request: KoauthRequest)
                 (implicit persistenceService: Persistence, ec: ExecutionContext): Future[KoauthResponse] = {
    verifyForAccessToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val argsF = Future {
          val consumerKey = request.oauthParamsMap(ConsumerKeyName)
          val requestToken = request.oauthParamsMap(TokenName)
          val verifier = request.oauthParamsMap(VerifierName)
          (consumerKey, requestToken, verifier)
        }
        argsF flatMap { args =>
          val (consumerKey, requestToken, verifier) = args
          persistenceService.whoAuthorizedRequesToken(consumerKey, requestToken, verifier)
        } flatMap {
          case None => successful(new ResponseUnauthorized(MessageNotAuthorized))
          case Some(username) =>
            for {
              (consumerKey, requestToken, verifier) <- argsF
              (token, secret) <- Future(generateTokenAndSecret)
              persisted <- persistenceService.persistAccessToken(consumerKey, token, secret, username)
            } yield createAccesTokenResponse(token, secret)
        }
    }
  }

  def oauthenticate(request: KoauthRequest)
                   (implicit persistenceService: Persistence, ec: ExecutionContext): Future[Either[ResponseNok, String]] = {
    verifyForOauthenticate(request) flatMap {
      case VerificationUnsupported(message) => successful(Left(new ResponseBadRequest(message)))
      case VerificationFailed(message) => successful(Left(new ResponseUnauthorized(message)))
      case VerificationOk =>
        for {
          consumerKey <- Future(request.oauthParamsMap(ConsumerKeyName))
          token <- Future(request.oauthParamsMap(TokenName))
          username <- persistenceService.getUsername(consumerKey, token)
        } yield Right(username)
    }
  }
}

object ProviderServiceFactory {

  def createDefaultOauthService = new CustomProviderService(getDefaultOauthVerifier)

  def createCustomOauthService(oauthVerifier: Verifier) = new CustomProviderService(oauthVerifier)
}
