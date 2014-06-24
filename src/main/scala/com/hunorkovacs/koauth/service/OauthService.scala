package com.hunorkovacs.koauth.service

import scala.concurrent.{Await, ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.OauthExtractor._
import com.hunorkovacs.koauth.service.OauthVerifier._
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.exception.{OauthUnauthorizedException, OauthBadRequestException}
import com.hunorkovacs.koauth.domain.OauthResponseOk
import com.hunorkovacs.koauth.domain.OauthRequest
import scala.util.{Failure, Success}
import com.hunorkovacs.koauth.domain.OauthParams._
import scala.concurrent.duration.Duration.Inf

object OauthService {

  def requestToken(request: OauthRequest)
                  (implicit persistenceService: OauthPersistence, ec: ExecutionContext): Future[OauthResponse] = {
    val enhancedRequestF = enhanceRequest(request)
    enhancedRequestF.flatMap(verifyForRequestToken) flatMap {
      case VerificationOk =>
        for {
          (token, secret) <- generateTokenAndSecret
          consumerKey <- enhancedRequestF.map(r => r.oauthParamsMap.applyOrElse(consumerKeyName, x => ""))
          callback <- enhancedRequestF.map(r => r.oauthParamsMap.applyOrElse(callbackName, x => ""))
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
      username = enhancedRequest.oauthParamsMap.applyOrElse(usernameName, x => "br")
      password = enhancedRequest.oauthParamsMap.applyOrElse(passwordName, x => "ab")
      auth <- persistenceService.authenticate(username, password)
    } yield auth) flatMap {
      case true =>
        for {
          enhancedRequest <- enhanceRequest(request)
          consumerKey = enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => "")
          requestToken = enhancedRequest.oauthParamsMap.applyOrElse(tokenName, x => "")
          username = enhancedRequest.oauthParamsMap.applyOrElse(usernameName, x => "")
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
    enhancedRequestF.flatMap(verifyForAccessToken) flatMap {
      case VerificationFailed => Future(new OauthResponseUnauthorized("Bad sign."))
      case VerificationUnsupported => Future(new OauthResponseBadRequest("Not supp."))
      case VerificationOk =>
        (for {
          enhancedRequest <- enhanceRequest(request)
          consumerKey = enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => "")
          requestToken = enhancedRequest.oauthParamsMap.applyOrElse(tokenName, x => "")
          user <- persistenceService.whoAuthorizedRequesToken(consumerKey, requestToken)
        } yield user) flatMap {
          case None => Future(new OauthResponseUnauthorized("Request Token not authorized"))
          case Some(username) =>
            for {
              enhancedRequest <- enhanceRequest(request)
              consumerKey = enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => "")
              (token, secret) <- generateTokenAndSecret
              accessToken <- persistenceService.persistAccessToken(consumerKey, token, secret, username)
              response <- createAccesTokenResponse(token, secret)
            } yield response
        }
    }
  }

  def oauthenticate(requestF: Future[OauthRequest])(implicit persistenceService: OauthPersistence,
                                                    ec: ExecutionContext): (Future[String], Future[Rights]) = {
    val headerF = requestF.map(oauthRequestF => oauthRequestF.authorizationHeader)
    val allOauthParamsF = extractAllOauthParams(headerF)
    val requiredOauthParamsF = extractSpecificOauthParams(allOauthParamsF, OauthenticateRequiredParams)

    val consumerKeyF = requiredOauthParamsF.map(p => p.consumerKey)
    val tokenF = requiredOauthParamsF.map(p => p.token)
    val tupleF = persistenceService.getToken(consumerKeyF, tokenF)
    val consumerSecretF = tupleF.map(t => t._1)
    val tokenSecretF = tupleF.map(t => t._2)
    val usernameF = tupleF.map(t => t._3)
    val rightsF = tupleF.map(t => t._4)

    val completedOauthParamsF = for {
      consumerSecret <- consumerSecretF
      tokenSecret <- tokenSecretF
      requiredOauthParams <- requiredOauthParamsF
    } yield {
      new OauthParamsBuilder()
        .withOauthParams(requiredOauthParams)
        .withParam(consumerSecretName, consumerSecret)
        .withParam(OauthParams.tokenSecretName, tokenSecret)
        .build()
    }

    verify(requestF, allOauthParamsF, completedOauthParamsF)

    (usernameF, rightsF)
  }
}
