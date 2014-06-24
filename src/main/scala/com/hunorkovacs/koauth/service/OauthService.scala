package com.hunorkovacs.koauth.service

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.OauthExtractor._
import com.hunorkovacs.koauth.service.OauthVerifier._
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthRequest
import com.hunorkovacs.koauth.domain.OauthParams._

object OauthService {

  def requestToken(request: OauthRequest)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    val enhancedRequestF = enhanceRequest(request)
    enhancedRequestF.flatMap(verifyForRequestToken) flatMap {
      case VerificationOk =>
        for {
          (token, secret) <- generateTokenAndSecret
          consumerKey <- enhancedRequestF.map(r => r.oauthParamsMap(consumerKeyName))
          callback <- enhancedRequestF.map(r => r.oauthParamsMap(callbackName))
          persisted <- persistenceService.persistRequestToken(consumerKey, token, secret, callback)
          response <- createRequestTokenResponse(token, secret, callback)
        } yield response
      case VerificationFailed => Future(new OauthResponseUnauthorized("Bad sign."))
      case VerificationUnsupported => Future(new OauthResponseBadRequest("Not supp."))
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
      case VerificationFailed => Future(new OauthResponseUnauthorized("Bad sign."))
      case VerificationUnsupported => Future(new OauthResponseBadRequest("Not supp."))
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
      case VerificationUnsupported => Future(Left(new OauthResponseBadRequest("Not supp.")))
      case VerificationFailed => Future(Left(new OauthResponseUnauthorized("Bad sign.")))
      case VerificationOk =>
        for {
          consumerKey <- enhancedRequestF.map(r => r.oauthParamsMap(consumerKeyName))
          token <- enhancedRequestF.map(r => r.oauthParamsMap(tokenName))
          username <- persistenceService.getUsername(consumerKey, token)
        } yield Right(username)
    }
  }
}
