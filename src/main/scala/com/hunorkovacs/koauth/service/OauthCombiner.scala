package com.hunorkovacs.koauth.service

import java.net.URLEncoder
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthRequest, OauthResponseOk, OauthParams}
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.domain.OauthRequest
import com.hunorkovacs.koauth.domain.OauthResponseOk

object OauthCombiner {

  def URLEncode(s: String) = URLEncoder.encode(s, OauthExtractor.UTF8).replaceAll("+", "%20")

  def concatItemsForSignature(requestF: Future[OauthRequest], allOauthParams: Future[List[(String, String)]])
                             (implicit ec: ExecutionContext): Future[String] = {
    val methodF = requestF.map(r => r.method)
    val urlF = requestF.map(r => r.urlWithoutParams)
    val normalizedOauthParametersF = normalizeOauthParamsForSignature(allOauthParams)
    concatItems(List(methodF, urlF, normalizedOauthParametersF))
  }

  private def normalizeOauthParamsForSignature(allOauthParamsF: Future[List[(String, String)]])
                                              (implicit ec: ExecutionContext): Future[String] = {
    val filteredParams = allOauthParamsF map { allOauthParams =>
      allOauthParams filterNot { keyValue =>
        keyValue._1 == OauthParams.realmName && keyValue._1 == OauthParams.signatureName
      }
    }
    combineOauthParams(filteredParams)
  }

  def combineOauthParams(keyValueListF: Future[List[(String, String)]])
                        (implicit ec: ExecutionContext): Future[String] = {
    val itemListF = keyValueListF map { keyValueList =>
      val paramsTogetherEncoded = keyValueList map { keyValue =>
        val (key, value) = keyValue
        URLEncode(key) + "=" + URLEncode(value)
      }
      paramsTogetherEncoded.sorted
    }
    concatItems(itemListF)
  }

  def concatItems(itemsFList: List[Future[String]])(implicit ec: ExecutionContext): Future[String] = {
    val itemListF = Future.sequence(itemsFList)
    concatItems(itemListF)
  }

  def concatItems(itemListF: Future[List[String]])(implicit ec: ExecutionContext): Future[String] = {
    itemListF map { itemList =>
      itemList.map(item => URLEncode(item)).mkString("&")
    }
  }

  def createRequestTokenResponse(tokenF: Future[String], secretF: Future[String],callbackF: Future[String])
                                (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    val listF = for {
      token <- tokenF
      secret <- secretF
      callback <- callbackF
    } yield {
      List((OauthParams.tokenName, token),
        (OauthParams.tokenSecretName, secret),
        (OauthParams.callbackName, callback))
    }
    combineOauthParams(listF) map { body: String =>
      new OauthResponseOk(body)
    }
  }

  def createAuthorizeResponse(tokenF: Future[String], verifierF: Future[String])
                             (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    val paramsF = for {
      token <- tokenF
      verifier <- verifierF
    } yield {
      List((OauthParams.tokenName, token), (OauthParams.verifierName, verifier))
    }
    combineOauthParams(paramsF).map(body => new OauthResponseOk(body))
  }

  def createAccesTokenResponse(tokenF: Future[String], secretF: Future[String])
                              (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    val paramsF = for {
      token <- tokenF
      secret <- secretF
    } yield {
      List((OauthParams.tokenName, token), (OauthParams.tokenSecretName, secret))
    }
    combineOauthParams(paramsF).map(body => new OauthResponseOk(body))
  }
}
