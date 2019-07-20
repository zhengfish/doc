
How It Works

.. code-block:: rst

    如何工作

The objective of Let’s Encrypt and the ACME protocol is to make it possible to set up an HTTPS server and have it automatically obtain a browser-trusted certificate, without any human intervention. This is accomplished by running a certificate management agent on the web server.

.. code-block:: rst

    Let’s Encrypt和ACME协议的共同目标，是没有任何人为干预地建立一个HTTPS服务器并能自动获得浏览器信任的证书。这是通过在Web服务器上运行证书管理代理来完成的。

To understand how the technology works, let’s walk through the process of setting up https://example.com/ with a certificate management agent that supports Let’s Encrypt.

.. code-block:: rst

    让我们以设置https://example.com/支持Let’s Encrypt的管理代理的流程为例，来理解技术上如何运行。

There are two steps to this process. First, the agent proves to the CA that the web server controls a domain. Then, the agent can request, renew, and revoke certificates for that domain.

.. code-block:: rst

    整个个过程分两个步骤。首先，代理向服务器证明了该Web服务器控制了某个域。其次，代理可以请求、更新和撤销该域的证书。

Domain Validation

Let’s Encrypt identifies the server administrator by public key. The first time the agent software interacts with Let’s Encrypt, it generates a new key pair and proves to the Let’s Encrypt CA that the server controls one or more domains. This is similar to the traditional CA process of creating an account and adding domains to that account.


.. code-block:: rst

    Let’s Encrypt通过公共密钥来标识服务器管理员。一开始代理软件与Let’s Encrypt进行交互，生成一个新的密钥对，并向Let’s Encrypt证明该服务器控制了一个或多个域。这有些类似于传统的建立一个帐户，并添加域到该帐户的过程。

To kick off the process, the agent asks the Let’s Encrypt CA what it needs to do in order to prove that it controls example.com. The Let’s Encrypt CA will look at the domain name being requested and issue one or more sets of challenges. These are different ways that the agent can prove control of the domain. For example, the CA might give the agent a choice of either:

    Provisioning a DNS record under example.com, or
    Provisioning an HTTP resource under a well-known URI on https://example.com/


.. code-block:: rst

    为了开始这个过程，代理问Let’s Encrypt 的CA需要什么才能证明它控制example.com。Let’s Encrypt的CA将查看被请求的域名，并发出一个或多套的挑战。以下这些都是代理可以证明不同的方式对域的控制。例如，CA可能给代理一个选择：
    * 配置一个example.com名下的DNS记录，或
    * 配置一个https://example.com/已知的的URI名下的HTTP资源

Along with the challenges, the Let’s Encrypt CA also provides a nonce that the agent must sign with its private key pair to prove that it controls the key pair.
Requesting challenges to validate example.com

.. code-block:: rst

    在挑战过程中，Let’s Encrypt的CA会提供一个临时随机数NONCE，代理必须用自己的私钥对其签名以证明它控制该密钥对。
    请求挑战以验证example.com

The agent software completes one of the provided sets of challenges. Let’s say it is able to accomplish the second task above: it creates a file on a specified path on the https://example.com site. The agent also signs the provided nonce with its private key. Once the agent has completed these steps, it notifies the CA that it’s ready to complete validation.

.. code-block:: rst

    代理软件要完成所提供的多套挑战的其中之一。比方说，它可以完成第二个任务：它创建https://example.com网站上指定的路径上的一个文件。该代理还用自己的私钥签署了CA提供的临时随机数。一旦代理完成这些步骤，它会通知CA它已经准备完成该验证。

Then, it’s the CA’s job to check that the challenges have been satisfied. The CA verifies the signature on the nonce, and it attempts to download the file from the web server and make sure it has the expected content.
Requesting authorization to act for example.com

If the signature over the nonce is valid, and the challenges check out, then the agent identified by the public key is authorized to do certificate management for example.com. We call the key pair the agent used an “authorized key pair” for example.com.
Certificate Issuance and Revocation

Once the agent has an authorized key pair, requesting, renewing, and revoking certificates is simple—just send certificate management messages and sign them with the authorized key pair.

To obtain a certificate for the domain, the agent constructs a PKCS#10 Certificate Signing Request that asks the Let’s Encrypt CA to issue a certificate for example.com with a specified public key. As usual, the CSR includes a signature by the private key corresponding to the public key in the CSR. The agent also signs the whole CSR with the authorized key for example.com so that the Let’s Encrypt CA knows it’s authorized.

When the Let’s Encrypt CA receives the request, it verifies both signatures. If everything looks good, it issues a certificate for example.com with the public key from the CSR and returns it to the agent.
Requesting a certificate for example.com

Revocation works in a similar manner. The agent signs a revocation request with the key pair authorized for example.com, and the Let’s Encrypt CA verifies that the request is authorized. If so, it publishes revocation information into the normal revocation channels (i.e., CRLs, OCSP), so that relying parties such as browsers can know that they shouldn’t accept the revoked certificate.
Requesting revocation of a certificate for example.com

