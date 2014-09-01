package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics._
import VerifierObject.{MessageNotAuthorized, MessageUserInexistent}
import com.hunorkovacs.koauth.service.Generator._
import com.hunorkovacs.koauth.service.provider.persistence.Persistence

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

trait ProviderService {

  def requestToken(request: KoauthRequest): Future[KoauthResponse]

  def authorize(request: KoauthRequest): Future[KoauthResponse]

  def accessToken(request: KoauthRequest): Future[KoauthResponse]

  def oauthenticate(request: KoauthRequest): Future[Either[KoauthResponse, String]]
}

protected class CustomProviderService(private val oauthVerifier: Verifier,
                                      private val persistence: Persistence,
                                      private val ec: ExecutionContext) extends ProviderService {

  implicit private def implicitEc = ec
  import oauthVerifier._

  def requestToken(request: KoauthRequest): Future[KoauthResponse] = {
    verifyForRequestToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val callback = request.oauthParamsMap(CallbackName)
        val nonce = request.oauthParamsMap(NonceName)
        val (token, secret) = generateTokenAndSecret
        persistence.persistNonce(nonce, consumerKey, "") flatMap { _ =>
          persistence.persistRequestToken(consumerKey, token, secret, callback)
        } map { _ =>
          createRequestTokenResponse(token, secret, callback)
        }
    }
  }

  def authorize(request: KoauthRequest): Future[KoauthResponse] = {
    verifyForAuthorize(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val requestToken = request.oauthParamsMap(TokenName)
        val username = request.oauthParamsMap(UsernameName)
        val verifier = generateVerifier
        val nonce = request.oauthParamsMap(NonceName)
        persistence.persistNonce(nonce, consumerKey, requestToken) flatMap { _ =>
          persistence.authorizeRequestToken(consumerKey, requestToken, username, verifier)
        } map { _ =>
          createAuthorizeResponse(requestToken, verifier)
        }
    }
  }

  def accessToken(request: KoauthRequest): Future[KoauthResponse] = {
    verifyForAccessToken(request) flatMap {
      case VerificationFailed(message) => successful(new ResponseUnauthorized(message))
      case VerificationUnsupported(message) => successful(new ResponseBadRequest(message))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val requestToken = request.oauthParamsMap(TokenName)
        val verifier = request.oauthParamsMap(VerifierName)
        persistence.whoAuthorizedRequestToken(consumerKey, requestToken, verifier) flatMap {
          case None => successful(new ResponseUnauthorized(MessageNotAuthorized))
          case Some(username) =>
            val (token, secret) = generateTokenAndSecret
            val nonce = request.oauthParamsMap(NonceName)
            persistence.persistNonce(nonce, consumerKey, requestToken) flatMap { _ =>
              persistence.persistAccessToken(consumerKey, token, secret, username)
            } map { _ =>
              createAccesTokenResponse(token, secret)
            }
        }
    }
  }

  def oauthenticate(request: KoauthRequest): Future[Either[ResponseNok, String]] = {
    verifyForOauthenticate(request) flatMap {
      case VerificationUnsupported(message) => successful(Left(new ResponseBadRequest(message)))
      case VerificationFailed(message) => successful(Left(new ResponseUnauthorized(message)))
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        val token = request.oauthParamsMap(TokenName)
        val nonce = request.oauthParamsMap(NonceName)
        persistence.getUsername(consumerKey, token) flatMap {
          case None => successful(Left(new ResponseUnauthorized(MessageUserInexistent)))
          case Some(username) => persistence.persistNonce(nonce, consumerKey, token).map(_ => Right(username))
        }
    }
  }
}

object ProviderServiceFactory {

  def createProviderService(persistence: Persistence, ec: ExecutionContext): ProviderService = {
    val verifier = new CustomVerifier(persistence, ec)
    new CustomProviderService(verifier, persistence, ec)
  }
}
