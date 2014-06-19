package com.hunorkovacs.koauth.service

import java.net.URLEncoder
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthRequest, OauthResponseOk, OauthParams}
import com.hunorkovacs.koauth.service.TokenGenerator._
import com.hunorkovacs.koauth.domain.OauthRequest
import com.hunorkovacs.koauth.domain.OauthResponseOk

object OauthCombiner {

  def URLEncode(s: String) = URLEncoder.encode(s, OauthExtractor.UTF8).replaceAll("+", "%20")

  def concatItemsForSignature(request: OauthRequest, allParamsList: List[(String, String)])
                             (implicit ec: ExecutionContext): Future[String] = {
    normalizeOauthParamsForSignature(allParamsList) flatMap { n =>
      concatItems(List(request.method, request.urlWithoutParams, n))
    }
  }

  private def normalizeOauthParamsForSignature(allParamsList: List[(String, String)])
                                              (implicit ec: ExecutionContext): Future[String] = {
    Future {
      allParamsList filterNot { keyValue =>
        keyValue._1 == OauthParams.realmName && keyValue._1 == OauthParams.signatureName
      }
    } flatMap combineOauthParams
  }

  def combineOauthParams(keyValueList: List[(String, String)])
                        (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val paramsTogetherEncoded = keyValueList map { keyValue =>
        val (key, value) = keyValue
        URLEncode(key) + "=" + URLEncode(value)
      }
      paramsTogetherEncoded.sorted
    } flatMap concatItems
  }

//  def concatItems(itemsFList: List[Future[String]])(implicit ec: ExecutionContext): Future[String] = {
//    val itemListF = Future.sequence(itemsFList)
//    concatItems(itemListF)
//  }

  def concatItems(itemList: List[String])(implicit ec: ExecutionContext): Future[String] = {
    Future {
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
