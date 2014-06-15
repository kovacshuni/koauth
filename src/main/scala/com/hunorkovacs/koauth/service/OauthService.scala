package com.hunorkovacs.koauth.service

import scala.concurrent.{ExecutionContext, Future}
import scala.async.Async.{async, await}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.OauthExtractor._
import com.hunorkovacs.koauth.service.OauthVerifier._
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.exception.OauthBadRequestException
import com.hunorkovacs.koauth.domain.OauthResponseOk
import com.hunorkovacs.koauth.domain.exception.OauthBadRequestException
import com.hunorkovacs.koauth.domain.OauthRequest

object OauthService {

  case class RequestTokenResources(consumerKey: String,
                                   token: String,
                                   tokenSecret: String,
                                   response: OauthResponseOk)

  def requestToken(requestF: Future[OauthRequest])(implicit persistenceService: OauthPersistence,
                   ec: ExecutionContext): Future[OauthResponseOk] = {
    val headerF = requestF.map(oauthRequestF => oauthRequestF.authorizationHeader)
    val allOauthParamsF = extractAllOauthParams(headerF)
    val requiredOauthParamsF = extractSpecificOauthParams(allOauthParamsF, RequestTokenRequiredParams)
    verify(requestF, allOauthParamsF, requiredOauthParamsF)
    val (tokenF, secretF) = generateTokenAndSecret
    val consumerKeyF = requiredOauthParamsF.map(params => params.consumerKey)
    val responseF = createRequestTokenResponse(tokenF, secretF, Future("callbackabc"))
    val requestTokenResourcesF = for {
      token <- tokenF
      secret <- secretF
      consumerKey <- consumerKeyF
      response <- responseF
    } yield new RequestTokenResources(consumerKey, token, secret, response)
    persistenceService.persistRequestToken(requestTokenResourcesF)
    responseF
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
        .withProperty(OauthParams.consumerSecretName, consumerSecret)
        .withProperty(OauthParams.tokenSecretName, tokenSecret)
        .build()
    }

    verify(requestF, allOauthParamsF, completedOauthParamsF)

    (usernameF, rightsF)
  }
}
