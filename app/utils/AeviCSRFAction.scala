package utils

import play.api.mvc._
import scala.concurrent.Future
import java.security.SignatureException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.UUID
import org.joda.time.DateTime
import org.joda.time.Period
import play.api.Play.current
import org.apache.commons.codec.binary.Base64
import play.api.Logger
import play.api.mvc.BodyParsers._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher
import java.security.MessageDigest
import java.util.Arrays
import java.security.Key
import play.api.libs.json.Json

package object AeviKey {
    val getKey: Key = {
        val applicationSecret = current.configuration.getString("application.secret").getOrElse(throw new Exception("application secret is not configured"))

        val sha = MessageDigest.getInstance("SHA-1")
        val trimedKey = Arrays.copyOf(sha.digest(applicationSecret.getBytes("UTF-8")), 16)
        new SecretKeySpec(trimedKey, "AES")
    }
}

object GetAction extends ActionBuilder[Request] {
    def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[SimpleResult]) = {
        if (request.headers.get("token") == None) {
            val username = request.headers.get("username").get
            val token = encrypt(username)
            println("token => " + token)
        }
        block(request)
    }

    //  override def composeAction[A](action: Action[A]) = AeviCSRFCheck(action)

    def encrypt(username: String): String = {
        val nounce = UUID.randomUUID().toString
        val expiry = DateTime.now.plus(Period.minutes(15))
        val payload = Json.stringify(Json.obj("username" -> username, "expiry" -> expiry, "nounce" -> nounce)).getBytes("UTF8")

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val key = AeviKey.getKey
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val cipherText = cipher.doFinal(payload)
        new String(Base64.encodeBase64(cipherText))
    }
}

object PostAction extends ActionBuilder[Request] {
    def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[SimpleResult]) = {
        val decrypted = decrypt(request.headers.get("token").get)
        println("decrypted => " + decrypted)

        val username = (Json.parse(decrypted) \ "username").as[String]
        val expiry = (Json.parse(decrypted) \ "expiry")
        println ("username => " + username)
        println ("expiry => " + expiry)
        block(request)
    }
    //  override def composeAction[A](action: Action[A]) = CSRFAddToken(action)

    def decrypt(token: String) = {
        val key = AeviKey.getKey

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key);

        println("size: " + token.getBytes.length)
        val decoded = Base64.decodeBase64(token.getBytes)
        val newPlainText = cipher.doFinal(decoded);
        System.out.println("Finish decryption: ");

        new String(newPlainText, "UTF8")

    }
}

