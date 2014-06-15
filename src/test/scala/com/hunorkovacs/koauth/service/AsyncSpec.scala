package com.hunorkovacs.koauth.service

import scala.async.Async.async
import scala.concurrent.{Future, ExecutionContext, blocking}
import scala.util.Success
import scala.concurrent.duration._

class AsyncSpec extends org.specs2.mutable.Specification {

  implicit val ec = ExecutionContext.Implicits.global

   "awaiting" should {
     "simple" in {
       val f1 = Future {
         for (i <- 1 to 5) {
           println("f1 working")
           blocking(Thread.sleep(1000))
         }
         1
       }
       val f2 = Future {
         for (i <- 1 to 5) {
           println("f2 working")
           blocking(Thread.sleep(1000))
         }
         2
       }
       val f3 = async {
         val i1 = scala.async.Async.await(f1)
         val i2 = scala.async.Async.await(f2)
         val wF = async {
           for (i <- 1 to 3) {
             println("f3 working")
             blocking(Thread.sleep(1000))
           }
         }
         scala.async.Async.await(wF)
         val r = scala.async.Async.await(async(i1 + i2))
         r
       }

       scala.concurrent.Await.result(f3, 6.0.second) shouldEqual 3
     }
   }
}
