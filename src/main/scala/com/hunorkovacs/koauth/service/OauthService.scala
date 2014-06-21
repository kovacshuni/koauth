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
import com.hunorkovacs.koauth.domain.OauthParams.{callbackName, consumerKeyName, signatureMethodName}
import scala.concurrent.duration.Duration.Inf

object OauthService {

  def requestToken(request: OauthRequest)(implicit persistenceService: OauthPersistence,
                   ec: ExecutionContext): Future[OauthResponse] = {
    val enhancedRequestF = enhanceRequest(request)
    val consumerKeyF = enhancedRequestF.map(r => r.oauthParamsMap.applyOrElse(consumerKeyName, x => ""))

    val verificationF = for {
      enhancedRequest <- enhancedRequestF
      verification <- verify(enhancedRequest)
    } yield verification

    verificationF flatMap {
      case VerificationOk =>
        val (tokenF, secretF) = generateTokenAndSecret
        val callbackF = enhancedRequestF.map(r => r.oauthParamsMap.applyOrElse(callbackName, x => ""))
        for {
          token <- tokenF
          secret <- secretF
          consumerKey <- consumerKeyF
          callback <- callbackF
          persisted <- persistenceService.persistRequestToken(consumerKey, token, secret, callback)
          response <- createRequestTokenResponse(token, secret, callback)
        } yield response
      case VerificationFailed => Future(new OauthResponseOk("Bad sign."))
      case VerificationUnsupported => Future(new OauthResponseOk("Not supp."))
    }
  }

  def getRights(requestF: Future[OauthRequest])(implicit persistenceService: OauthPersistence,
                                                ec: ExecutionContext): Future[Rights] = {
    val tokenF = requestF map { request =>
      request.queryString(OauthParams.tokenName) match {
        case values: Seq[String] => {
          if (values.size != 1) throw OauthBadRequestException(s"$OauthParams.tokenName has more than one value.")
          else values.head
        }
        case _ => throw OauthBadRequestException(s"$OauthParams.tokenName not specified in request URL")
      }
    }
    persistenceService.getRights(tokenF)
  }

  def authorize(requestF: Future[OauthRequest])(implicit persistenceService: OauthPersistence,
                                                ec: ExecutionContext): Future[OauthResponseOk] = {
    val headerF = requestF.map(oauthRequestF => oauthRequestF.authorizationHeader)
    val allOauthParamsF = extractAllOauthParams(headerF)
    val requiredOauthParamsF = extractSpecificOauthParams(allOauthParamsF, AuthorizeRequiredParams)

    val consumerKeyF = requiredOauthParamsF.map(p => p.consumerKey)
    val tokenF = requiredOauthParamsF.map(p => p.token)
    val usernameF = requiredOauthParamsF.map(p => p.username)
    val passwordF = requiredOauthParamsF.map(p => p.password)
    persistenceService.authenticate(usernameF, passwordF)
    val verifierF = generateVerifier
    persistenceService.authorize(consumerKeyF, tokenF, usernameF, verifierF)
    createAuthorizeResponse(tokenF, verifierF)
  }

  def accessToken(requestF: Future[OauthRequest])(implicit persistenceService: OauthPersistence,
                                                  ec: ExecutionContext): Future[OauthResponseOk] = {
    val headerF = requestF.map(oauthRequestF => oauthRequestF.authorizationHeader)
    val allOauthParamsF = extractAllOauthParams(headerF)
    val requiredOauthParamsF = extractSpecificOauthParams(allOauthParamsF, AccessTokenRequiredParams)

    verify(requestF, allOauthParamsF, requiredOauthParamsF)

    val consumerKeyF = requiredOauthParamsF.map(p => p.consumerKey)
    val consumerSecretF = requiredOauthParamsF.map(p => p.consumerSecret)
    val tokenF = requiredOauthParamsF.map(p => p.token)
    val verifierF = requiredOauthParamsF.map(p => p.verifier)
    val usernameAndRightsF = persistenceService.whoAuthorizedRequestToken(consumerKeyF, tokenF, verifierF)
    val usernameF = usernameAndRightsF.map(f => f._1)
    val rightsF = usernameAndRightsF.map(f => f._2)

    val (accessTokenF, accessSecretF) = generateTokenAndSecret
    persistenceService.persistAccessToken(consumerKeyF, consumerSecretF,
      accessTokenF, accessSecretF,
      rightsF, usernameF)

    createAccesTokenResponse(accessTokenF, accessSecretF)
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
