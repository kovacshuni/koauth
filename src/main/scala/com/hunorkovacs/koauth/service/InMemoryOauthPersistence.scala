package com.hunorkovacs.koauth.service

import scala.concurrent.{ExecutionContext, Future}
import scala.collection.mutable.ListBuffer
import scala.async.Async.{async, await}
import com.hunorkovacs.koauth.service.OauthService.RequestTokenResources
import com.hunorkovacs.koauth.domain.Rights
import com.hunorkovacs.koauth.domain.exception.OauthUnauthorizedException

class InMemoryOauthPersistence extends OauthPersistence {

  case class RequestToken(consumerKey: String,
                          token: String,
                          tokenSecret: String,
                          rights: Rights,
                          username: Option[String],
                          verifier: Option[String],
                          authorized: Boolean)

  case class AccessToken(consumerKey: String,
                          consumerSecret: String,
                          token: String,
                          tokenSecret: String,
                          rights: Rights,
                          username: String)

  val requestTokenColl = new ListBuffer[RequestToken]()
  val accessTokenColl = new ListBuffer[AccessToken]()
  val usersColl = Map[String, String](("someUser", "somePass"))

  override def persistRequestToken(requestTokenResourcesF: Future[RequestTokenResources])
                                    (implicit ec: ExecutionContext): Future[Unit] = {
    async {
      val requestTokenResources = await(requestTokenResourcesF)
      requestTokenColl += RequestToken(requestTokenResources.consumerKey,
        requestTokenResources.token,
        requestTokenResources.tokenSecret,
        new Rights(List("all-rights")),
        None,
        None,
        authorized = false)
      Unit
    }
  }

  override def getRights(requestTokenF: Future[String])(implicit ec: ExecutionContext): Future[Rights] = {
    requestTokenF map { requestToken =>
      val token = requestTokenColl.filter(t => t.token == requestToken)
      if (token.isEmpty) new Rights(List.empty[String])
      else token.head.rights
    }
  }

  override def authenticate(usernameF: Future[String], passwordF: Future[String])
                            (implicit ec: ExecutionContext): Future[Unit] = {
    async {
      val username = await(usernameF)
      val actualPassword = await(passwordF)
      usersColl(username) match {
        case expectedPassword: String =>
          if (expectedPassword != actualPassword) throw new OauthUnauthorizedException("Invalid password.")
        case _ => throw new OauthUnauthorizedException("Invalid username.")
      }
      Unit
    }
  }

  override def authorize(consumerKeyF: Future[String], tokenF: Future[String],
                          usernameF: Future[String], verifierF: Future[String])
                         (implicit ec: ExecutionContext): Future[Unit] = {
    for {
      consumerKey <- consumerKeyF
      token <- tokenF
      username <- usernameF
      verifier <- verifierF
    } yield {
      val foundTokens = requestTokenColl filter { t =>
        t.token == token && t.consumerKey == consumerKey
      }
      if (foundTokens.isEmpty) throw new IllegalStateException("Token not found")
      val foundToken = foundTokens.head
      val i = requestTokenColl.indexOf(foundToken)
      requestTokenColl.remove(i)
      requestTokenColl += RequestToken(foundToken.consumerKey, foundToken.token, foundToken.tokenSecret,
        foundToken.rights, Some(username), Some(verifier), authorized = true)
      Unit
    }
  }

  override def whoAuthorizedRequestToken(consumerKeyF: Future[String], tokenF: Future[String],
                                          verifierF: Future[String])
                                          (implicit ec: ExecutionContext): Future[(String, Rights)] = {
    def verifierMatches(expectedVerifier: Option[String], actualVerifier: String): Boolean = {
      expectedVerifier match {
        case Some(v) => actualVerifier == v
        case None => false
      }
    }

    val foundTokenF = for {
      consumerKey <- consumerKeyF
      token <- tokenF
      verifier <- verifierF
    } yield {
      requestTokenColl find { t =>
        token == t.token &&
          consumerKey == t.consumerKey &&
          verifierMatches(t.verifier, verifier)
      }
    }
    foundTokenF map {
      case Some(t) => (t.username.get, t.rights)
      case None => throw new OauthUnauthorizedException("Request Token was not found or was not authorized.")
    }
  }

  override def persistAccessToken(consumerKeyF: Future[String], consumerSecretF: Future[String],
                         tokenF: Future[String], tokenSecretF: Future[String],
                         rightsF: Future[Rights], usernameF: Future[String])
                        (implicit ec: ExecutionContext): Future[Unit] = {
    for {
      consumerKey <- consumerKeyF
      consumerSecret <- consumerSecretF
      token <- tokenF
      tokenSecret <- tokenSecretF
      rights <- rightsF
      username <- usernameF
    } yield {
      accessTokenColl += new AccessToken(consumerKey,
        consumerSecret,
        token,
        tokenSecret,
        rights,
        username)
    }
  }

  override def getToken(consumerKeyF: Future[String], tokenF: Future[String])
                       (implicit ec: ExecutionContext): Future[(String, String, String, Rights)] = {
    def foundTokenF = for {
      consumerKey <- consumerKeyF
      token <- tokenF
    } yield {
      accessTokenColl find { actualToken =>
        actualToken.token == token
        actualToken.consumerKey == consumerKey
      }
    }
    foundTokenF map {
      case Some(t) => (t.consumerSecret, t.tokenSecret, t.username, t.rights)
      case None => throw new OauthUnauthorizedException("No such access token.")
    }
  }
}
