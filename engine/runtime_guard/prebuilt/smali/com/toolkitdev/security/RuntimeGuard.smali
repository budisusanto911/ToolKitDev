.class public Lcom/toolkitdev/security/RuntimeGuard;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/toolkitdev/security/RuntimeGuard$DerElement;,
        Lcom/toolkitdev/security/RuntimeGuard$ExitListener;,
        Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;
    }
.end annotation


# static fields
.field private static final FLAG_BOOTLOADER_PROP:I = 0x8

.field private static final FLAG_DEBUGGER_TRACER:I = 0x20

.field private static final FLAG_EMULATOR:I = 0x40

.field private static final FLAG_FRIDA_ACTIVE:I = 0x200

.field private static final FLAG_HIDDEN_ROOT_APP:I = 0x4

.field private static final FLAG_HOOK_FRAMEWORK:I = 0x10

.field private static final FLAG_MEMORY_HOOK:I = 0x100

.field private static final FLAG_ROOT_BINARY:I = 0x1

.field private static final FLAG_ROOT_MOUNT:I = 0x2

.field private static final FLAG_SELINUX_TAMPER:I = 0x80

.field private static final TAG:Ljava/lang/String; = "ToolKitDevGuard"

.field private static volatile sAttestationChecked:Z

.field private static volatile sCachedAttestationThreat:Ljava/lang/String;

.field private static volatile sDialogShownActivityHash:I

.field private static volatile sInstalled:Z

.field private static volatile sKillScheduled:Z

.field private static volatile sNativeLoaded:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 71
    const/4 v0, 0x0

    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z

    .line 72
    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sInstalled:Z

    .line 73
    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    .line 74
    const/4 v1, 0x0

    sput-object v1, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;

    .line 75
    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sKillScheduled:Z

    .line 76
    sput v0, Lcom/toolkitdev/security/RuntimeGuard;->sDialogShownActivityHash:I

    .line 80
    :try_start_0
    const-string v1, "tkdguard"

    invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 81
    const/4 v1, 0x1

    sput-boolean v1, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    goto :goto_0

    .line 82
    :catchall_0
    move-exception v1

    .line 83
    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z

    .line 84
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Native guard load failed: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "ToolKitDevGuard"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 86
    :goto_0
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 55
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method static synthetic access$100(Landroid/app/Activity;)V
    .locals 0

    .line 55
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->terminateActivityAndApp(Landroid/app/Activity;)V

    return-void
.end method

.method static synthetic access$200(Landroid/content/Context;Z)V
    .locals 0

    .line 55
    invoke-static {p0, p1}, Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;Z)V

    return-void
.end method

.method private static checkHardwareKeyAttestation()Ljava/lang/String;
    .locals 16

    .line 260
    const-string v0, "tricky"

    const-string v1, "aosp"

    const-string v2, "software attestation"

    const-string v3, "AndroidKeyStore"

    const-string v4, "ToolKitDevGuard"

    sget-boolean v5, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    if-eqz v5, :cond_0

    .line 261
    sget-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;

    return-object v0

    .line 263
    :cond_0
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v6, 0x18

    const/4 v7, 0x0

    const/4 v8, 0x1

    if-ge v5, v6, :cond_1

    .line 264
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    .line 265
    return-object v7

    .line 268
    :cond_1
    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "tkd_att_"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v9

    const-wide/32 v11, 0xffff

    and-long/2addr v9, v11

    invoke-virtual {v5, v9, v10}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    .line 269
    nop

    .line 271
    const/16 v6, 0x10

    :try_start_0
    new-array v6, v6, [B

    .line 272
    new-instance v9, Ljava/security/SecureRandom;

    invoke-direct {v9}, Ljava/security/SecureRandom;-><init>()V

    invoke-virtual {v9, v6}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 274
    const-string v9, "EC"

    invoke-static {v9, v3}, Ljava/security/KeyPairGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;

    move-result-object v9

    .line 276
    new-instance v10, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    const/4 v11, 0x4

    invoke-direct {v10, v5, v11}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    const-string v11, "SHA-256"

    filled-new-array {v11}, [Ljava/lang/String;

    move-result-object v11

    .line 278
    invoke-virtual {v10, v11}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setDigests([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    move-result-object v10

    .line 279
    invoke-virtual {v10, v6}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setAttestationChallenge([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    move-result-object v10

    .line 280
    invoke-virtual {v10}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    move-result-object v10

    .line 281
    invoke-virtual {v9, v10}, Ljava/security/KeyPairGenerator;->initialize(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 282
    invoke-virtual {v9}, Ljava/security/KeyPairGenerator;->generateKeyPair()Ljava/security/KeyPair;

    .line 284
    invoke-static {v3}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_7

    .line 285
    :try_start_1
    invoke-virtual {v3, v7}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 286
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->getCertificateChain(Ljava/lang/String;)[Ljava/security/cert/Certificate;

    move-result-object v9

    .line 287
    const/4 v10, 0x0

    if-eqz v9, :cond_d

    array-length v11, v9

    const/4 v12, 0x2

    if-ge v11, v12, :cond_2

    goto/16 :goto_6

    .line 294
    :cond_2
    const/4 v11, 0x0

    :goto_0
    array-length v12, v9

    if-ge v11, v12, :cond_a

    .line 295
    aget-object v12, v9, v11

    instance-of v12, v12, Ljava/security/cert/X509Certificate;

    if-eqz v12, :cond_7

    .line 296
    aget-object v12, v9, v11

    check-cast v12, Ljava/security/cert/X509Certificate;

    .line 297
    invoke-virtual {v12}, Ljava/security/cert/X509Certificate;->getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;

    move-result-object v13
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_6

    const-string v14, ""

    if-eqz v13, :cond_3

    :try_start_2
    invoke-virtual {v12}, Ljava/security/cert/X509Certificate;->getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;

    move-result-object v13

    invoke-virtual {v13}, Ljavax/security/auth/x500/X500Principal;->getName()Ljava/lang/String;

    move-result-object v13

    goto :goto_1

    :cond_3
    move-object v13, v14

    .line 298
    :goto_1
    invoke-virtual {v12}, Ljava/security/cert/X509Certificate;->getIssuerX500Principal()Ljavax/security/auth/x500/X500Principal;

    move-result-object v15

    if-eqz v15, :cond_4

    invoke-virtual {v12}, Ljava/security/cert/X509Certificate;->getIssuerX500Principal()Ljavax/security/auth/x500/X500Principal;

    move-result-object v12

    invoke-virtual {v12}, Ljavax/security/auth/x500/X500Principal;->getName()Ljava/lang/String;

    move-result-object v14

    .line 299
    :cond_4
    invoke-virtual {v13}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v12

    .line 300
    invoke-virtual {v14}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v13

    .line 301
    invoke-virtual {v12, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v14

    if-nez v14, :cond_5

    invoke-virtual {v13, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v14

    if-nez v14, :cond_5

    .line 302
    invoke-virtual {v12, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v14

    if-nez v14, :cond_5

    invoke-virtual {v13, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v14

    if-nez v14, :cond_5

    .line 303
    invoke-virtual {v12, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v12

    if-nez v12, :cond_5

    invoke-virtual {v13, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v12

    if-eqz v12, :cond_7

    .line 304
    :cond_5
    const-string v0, "Keystore Software Attestation / Fake Keybox terdeteksi (TEE tidak valid)"

    sput-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;

    .line 305
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    .line 306
    sget-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_6

    .line 336
    if-eqz v3, :cond_6

    .line 337
    :try_start_3
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v1

    .line 306
    :cond_6
    :goto_2
    return-object v0

    .line 309
    :cond_7
    add-int/lit8 v12, v11, 0x1

    :try_start_4
    array-length v13, v9
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_6

    if-ge v12, v13, :cond_9

    .line 311
    :try_start_5
    aget-object v11, v9, v11

    aget-object v13, v9, v12

    invoke-virtual {v13}, Ljava/security/cert/Certificate;->getPublicKey()Ljava/security/PublicKey;

    move-result-object v13

    invoke-virtual {v11, v13}, Ljava/security/cert/Certificate;->verify(Ljava/security/PublicKey;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 316
    goto :goto_4

    .line 312
    :catchall_1
    move-exception v0

    .line 313
    :try_start_6
    const-string v0, "Integritas sertifikat Hardware Attestation tidak valid (TrickyStore / Keybox spoofing)"

    sput-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;

    .line 314
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    .line 315
    sget-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 336
    if-eqz v3, :cond_8

    .line 337
    :try_start_7
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    goto :goto_3

    :catchall_2
    move-exception v1

    .line 315
    :cond_8
    :goto_3
    return-object v0

    .line 294
    :cond_9
    :goto_4
    move v11, v12

    goto/16 :goto_0

    .line 321
    :cond_a
    :try_start_8
    aget-object v0, v9, v10

    instance-of v0, v0, Ljava/security/cert/X509Certificate;

    if-eqz v0, :cond_c

    .line 322
    aget-object v0, v9, v10

    check-cast v0, Ljava/security/cert/X509Certificate;

    const-string v1, "1.3.6.1.4.1.11129.2.1.17"

    invoke-virtual {v0, v1}, Ljava/security/cert/X509Certificate;->getExtensionValue(Ljava/lang/String;)[B

    move-result-object v0

    .line 323
    if-eqz v0, :cond_c

    array-length v1, v0

    const/16 v2, 0x8

    if-le v1, v2, :cond_c

    .line 324
    const-string v1, "ro.boot.vbmeta.digest"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 325
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    invoke-static {v0, v6, v1, v2}, Lcom/toolkitdev/security/RuntimeGuard;->parseKeyAttestationExtension([B[BLjava/lang/String;I)Ljava/lang/String;

    move-result-object v0

    .line 326
    if-eqz v0, :cond_c

    .line 327
    sput-object v0, Lcom/toolkitdev/security/RuntimeGuard;->sCachedAttestationThreat:Ljava/lang/String;

    .line 328
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    .line 329
    nop

    .line 336
    if-eqz v3, :cond_b

    .line 337
    :try_start_9
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    goto :goto_5

    :catchall_3
    move-exception v1

    .line 329
    :cond_b
    :goto_5
    return-object v0

    .line 336
    :cond_c
    if-eqz v3, :cond_10

    .line 337
    :try_start_a
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    goto :goto_a

    :catchall_4
    move-exception v0

    goto :goto_a

    .line 288
    :cond_d
    :goto_6
    :try_start_b
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "KeyAttestation chain unavailable/short (len="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    if-nez v9, :cond_e

    goto :goto_7

    :cond_e
    array-length v10, v9

    :goto_7
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 289
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 290
    nop

    .line 336
    if-eqz v3, :cond_f

    .line 337
    :try_start_c
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_5

    goto :goto_8

    :catchall_5
    move-exception v0

    .line 290
    :cond_f
    :goto_8
    return-object v7

    .line 333
    :catchall_6
    move-exception v0

    goto :goto_9

    :catchall_7
    move-exception v0

    move-object v3, v7

    .line 334
    :goto_9
    :try_start_d
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "KeyAttestation skipped/failed: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, ": "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_8

    .line 336
    if-eqz v3, :cond_10

    .line 337
    :try_start_e
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 340
    :cond_10
    :goto_a
    sput-boolean v8, Lcom/toolkitdev/security/RuntimeGuard;->sAttestationChecked:Z

    .line 341
    return-object v7

    .line 336
    :catchall_8
    move-exception v0

    if-eqz v3, :cond_11

    .line 337
    :try_start_f
    invoke-virtual {v3, v5}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_9

    goto :goto_b

    :catchall_9
    move-exception v1

    .line 339
    :cond_11
    :goto_b
    throw v0
.end method

.method public static detectThreat(Landroid/content/Context;)Ljava/lang/String;
    .locals 5

    .line 671
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 673
    nop

    .line 674
    nop

    .line 675
    sget-boolean v1, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z

    const/4 v2, 0x0

    const-string v3, ""

    if-eqz v1, :cond_1

    .line 677
    :try_start_0
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->nativeScan()I

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 678
    if-eqz v1, :cond_0

    .line 679
    :try_start_1
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->nativeScanDetails()Ljava/lang/String;

    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    .line 681
    :catchall_0
    move-exception v4

    goto :goto_0

    :catchall_1
    move-exception v1

    const/4 v1, 0x0

    .line 682
    :goto_0
    const-string v4, "Integritas modul keamanan native (libtkdguard) terganggu"

    invoke-interface {v0, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 683
    :cond_0
    :goto_1
    goto :goto_2

    .line 685
    :cond_1
    const-string v1, "Pustaka keamanan native (libtkdguard.so) tidak termuat / dimodifikasi"

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    const/4 v1, 0x0

    .line 689
    :goto_2
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->checkHardwareKeyAttestation()Ljava/lang/String;

    move-result-object v4

    .line 690
    if-eqz v4, :cond_2

    .line 691
    invoke-interface {v0, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 695
    :cond_2
    and-int/lit16 v4, v1, 0x8f

    if-nez v4, :cond_4

    .line 696
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isDeviceRooted()Z

    move-result v4

    if-nez v4, :cond_4

    .line 697
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->isMagiskOrRootAppInstalled(Landroid/content/Context;)Z

    move-result p0

    if-eqz p0, :cond_3

    goto :goto_3

    :cond_3
    const/4 p0, 0x0

    goto :goto_4

    :cond_4
    :goto_3
    const/4 p0, 0x1

    .line 698
    :goto_4
    if-eqz p0, :cond_5

    .line 699
    const-string p0, "Perangkat Root / Magisk / KernelSU / APatch / Modul Hide terdeteksi"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 703
    :cond_5
    and-int/lit16 p0, v1, 0x200

    if-eqz p0, :cond_6

    .line 704
    const-string p0, "Frida Server / Dynamic Instrumentation aktif terdeteksi (port 27042)"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 708
    :cond_6
    and-int/lit16 p0, v1, 0x100

    if-eqz p0, :cond_7

    .line 709
    const-string p0, "Injeksi Memori / Zygisk / Shamiko / LSPlant Inline Hook terdeteksi pada pustaka sistem"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 711
    :cond_7
    and-int/lit8 p0, v1, 0x10

    if-nez p0, :cond_8

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isHookFrameworkDetected()Z

    move-result p0

    if-eqz p0, :cond_9

    .line 712
    :cond_8
    const-string p0, "Framework Hooking (Frida / LSPosed / Zygisk / Xposed / Hide Module) terdeteksi"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 716
    :cond_9
    and-int/lit8 p0, v1, 0x40

    if-nez p0, :cond_a

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isEmulatorDetected()Z

    move-result p0

    if-eqz p0, :cond_b

    .line 717
    :cond_a
    const-string p0, "Lingkungan Emulator / Virtual Device terdeteksi"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 721
    :cond_b
    and-int/lit8 p0, v1, 0x20

    if-nez p0, :cond_c

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isTracerOrDebuggerAttached()Z

    move-result p0

    if-eqz p0, :cond_d

    .line 722
    :cond_c
    const-string p0, "Debugger / Tracer aktif terdeteksi pada proses aplikasi"

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 725
    :cond_d
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result p0

    if-eqz p0, :cond_e

    .line 726
    const/4 p0, 0x0

    return-object p0

    .line 729
    :cond_e
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 730
    nop

    :goto_5
    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v1

    if-ge v2, v1, :cond_10

    .line 731
    if-lez v2, :cond_f

    const-string v1, "\n\u2022 "

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 732
    :cond_f
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 730
    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    .line 734
    :cond_10
    if-eqz v3, :cond_11

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v0

    if-lez v0, :cond_11

    .line 735
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Native diagnostics: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "ToolKitDevGuard"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 737
    :cond_11
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static enforceSecurity(Landroid/content/Context;)V
    .locals 1

    .line 835
    const/4 v0, 0x1

    invoke-static {p0, v0}, Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;Z)V

    .line 836
    return-void
.end method

.method private static enforceSecurity(Landroid/content/Context;Z)V
    .locals 3

    .line 839
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->detectThreat(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v0

    .line 840
    if-nez v0, :cond_0

    .line 841
    return-void

    .line 844
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "SECURITY BLOCK TRIGGERED: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "ToolKitDevGuard"

    invoke-static {v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 846
    instance-of v1, p0, Landroid/app/Activity;

    if-eqz v1, :cond_4

    .line 847
    check-cast p0, Landroid/app/Activity;

    .line 848
    invoke-static {p0, v0}, Lcom/toolkitdev/security/RuntimeGuard;->lockActivitySurface(Landroid/app/Activity;Ljava/lang/String;)V

    .line 849
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->scheduleFailsafeKill(Landroid/app/Activity;)V

    .line 851
    if-eqz p1, :cond_3

    invoke-virtual {p0}, Landroid/app/Activity;->isFinishing()Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    .line 854
    :cond_1
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result p1

    .line 855
    sget v1, Lcom/toolkitdev/security/RuntimeGuard;->sDialogShownActivityHash:I

    if-ne v1, p1, :cond_2

    .line 856
    return-void

    .line 858
    :cond_2
    sput p1, Lcom/toolkitdev/security/RuntimeGuard;->sDialogShownActivityHash:I

    .line 861
    :try_start_0
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Perangkat Anda terdeteksi memiliki pelanggaran keamanan:\n\n\u2022 "

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, "\n\nDemi melindungi data dan transaksi Anda, seluruh akses & transaksi diblokir pada perangkat ini."

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    .line 865
    new-instance v0, Landroid/app/AlertDialog$Builder;

    const v1, 0x10302d1

    invoke-direct {v0, p0, v1}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;I)V

    .line 867
    const-string v1, "\u26a0\ufe0f Peringatan Keamanan Perangkat"

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    .line 868
    invoke-virtual {v0, p1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    .line 869
    const/4 p1, 0x0

    invoke-virtual {v0, p1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;

    .line 870
    const-string v1, "Keluar Aplikasi"

    new-instance v2, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;

    invoke-direct {v2, p0}, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;-><init>(Landroid/app/Activity;)V

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    .line 871
    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->create()Landroid/app/AlertDialog;

    move-result-object v0

    .line 872
    invoke-virtual {v0, p1}, Landroid/app/AlertDialog;->setCanceledOnTouchOutside(Z)V

    .line 873
    new-instance p1, Lcom/toolkitdev/security/RuntimeGuard$3;

    invoke-direct {p1, p0}, Lcom/toolkitdev/security/RuntimeGuard$3;-><init>(Landroid/app/Activity;)V

    invoke-virtual {v0, p1}, Landroid/app/AlertDialog;->setOnCancelListener(Landroid/content/DialogInterface$OnCancelListener;)V

    .line 879
    new-instance p1, Lcom/toolkitdev/security/RuntimeGuard$4;

    invoke-direct {p1, p0}, Lcom/toolkitdev/security/RuntimeGuard$4;-><init>(Landroid/app/Activity;)V

    invoke-virtual {v0, p1}, Landroid/app/AlertDialog;->setOnDismissListener(Landroid/content/DialogInterface$OnDismissListener;)V

    .line 885
    new-instance p1, Lcom/toolkitdev/security/RuntimeGuard$5;

    invoke-direct {p1, p0}, Lcom/toolkitdev/security/RuntimeGuard$5;-><init>(Landroid/app/Activity;)V

    invoke-virtual {v0, p1}, Landroid/app/AlertDialog;->setOnKeyListener(Landroid/content/DialogInterface$OnKeyListener;)V

    .line 895
    invoke-virtual {v0}, Landroid/app/AlertDialog;->show()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 896
    return-void

    .line 897
    :catchall_0
    move-exception p1

    .line 898
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->terminateActivityAndApp(Landroid/app/Activity;)V

    .line 899
    return-void

    .line 852
    :cond_3
    :goto_0
    return-void

    .line 903
    :cond_4
    if-eqz p0, :cond_5

    .line 905
    :try_start_1
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Keamanan perangkat tidak memenuhi syarat: "

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const/4 v0, 0x1

    invoke-static {p0, p1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p0

    invoke-virtual {p0}, Landroid/widget/Toast;->show()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_1

    .line 906
    :catchall_1
    move-exception p0

    :goto_1
    nop

    .line 908
    :cond_5
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->terminateApp()V

    .line 909
    return-void
.end method

.method private static fileExists(Ljava/lang/String;)Z
    .locals 1

    .line 95
    :try_start_0
    new-instance v0, Ljava/io/File;

    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return p0

    .line 96
    :catchall_0
    move-exception p0

    .line 97
    const/4 p0, 0x0

    return p0
.end method

.method private static getProp(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 112
    sget-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z

    if-eqz v0, :cond_1

    .line 114
    :try_start_0
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->nativeGetProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 115
    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    if-lez v1, :cond_0

    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p0

    .line 116
    :catchall_0
    move-exception v0

    :cond_0
    nop

    .line 118
    :cond_1
    nop

    .line 120
    const/4 v0, 0x0

    :try_start_1
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v1

    const-string v2, "getprop"

    filled-new-array {v2, p0}, [Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object p0

    .line 121
    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/InputStreamReader;

    invoke-virtual {p0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object p0

    invoke-direct {v2, p0}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 122
    :try_start_2
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object p0

    .line 123
    if-eqz p0, :cond_2

    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 126
    nop

    .line 127
    :try_start_3
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception v0

    .line 123
    :goto_0
    return-object p0

    .line 126
    :cond_2
    nop

    .line 127
    :try_start_4
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    goto :goto_2

    :catchall_2
    move-exception p0

    goto :goto_2

    .line 124
    :catchall_3
    move-exception p0

    move-object v0, v1

    goto :goto_1

    :catchall_4
    move-exception p0

    .line 126
    :goto_1
    if-eqz v0, :cond_3

    .line 127
    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 130
    :cond_3
    :goto_2
    const-string p0, ""

    return-object p0
.end method

.method private static hasPackage(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 1

    .line 102
    const/4 v0, 0x0

    if-eqz p0, :cond_1

    if-nez p1, :cond_0

    goto :goto_0

    .line 104
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    invoke-virtual {p0, p1, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    const/4 p0, 0x1

    return p0

    .line 106
    :catchall_0
    move-exception p0

    .line 107
    return v0

    .line 102
    :cond_1
    :goto_0
    return v0
.end method

.method private static inspectAuthorizationListForRootOfTrust([BLcom/toolkitdev/security/RuntimeGuard$DerElement;Ljava/lang/String;)Ljava/lang/String;
    .locals 10

    .line 445
    const/4 v0, 0x0

    if-eqz p1, :cond_d

    iget-boolean v1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->constructed:Z

    if-nez v1, :cond_0

    goto/16 :goto_5

    .line 446
    :cond_0
    iget v1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    .line 447
    iget v2, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget p1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v2, p1

    .line 448
    :goto_0
    if-ge v1, v2, :cond_c

    .line 449
    invoke-static {p0, v1, v2}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object p1

    .line 450
    if-nez p1, :cond_1

    goto/16 :goto_4

    .line 451
    :cond_1
    iget v1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->nextPos:I

    .line 453
    iget v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagClass:I

    const/4 v4, 0x2

    if-ne v3, v4, :cond_b

    iget v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagNumber:I

    const/16 v5, 0x2c0

    if-ne v3, v5, :cond_b

    .line 454
    iget v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v5, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget p1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v5, p1

    invoke-static {p0, v3, v5}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object p1

    .line 455
    if-eqz p1, :cond_a

    iget-boolean v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->constructed:Z

    if-nez v3, :cond_2

    goto/16 :goto_3

    .line 456
    :cond_2
    iget v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    .line 457
    iget v5, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget p1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v5, p1

    .line 458
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 459
    :goto_1
    if-ge v3, v5, :cond_4

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v6

    const/4 v7, 0x6

    if-ge v6, v7, :cond_4

    .line 460
    invoke-static {p0, v3, v5}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object v3

    .line 461
    if-nez v3, :cond_3

    goto :goto_2

    .line 462
    :cond_3
    invoke-interface {p1, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 463
    iget v3, v3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->nextPos:I

    .line 464
    goto :goto_1

    .line 465
    :cond_4
    :goto_2
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v3

    const/4 v5, 0x3

    if-lt v3, v5, :cond_b

    .line 466
    const/4 v3, 0x0

    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    .line 467
    iget v7, v6, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v8, v6, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v6, v6, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v8, v6

    invoke-static {p0, v7, v8}, Ljava/util/Arrays;->copyOfRange([BII)[B

    move-result-object v6

    .line 468
    const/4 v7, 0x1

    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    .line 469
    iget v9, v8, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    if-lez v9, :cond_5

    iget v8, v8, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    aget-byte v8, p0, v8

    if-eqz v8, :cond_5

    const/4 v3, 0x1

    .line 470
    :cond_5
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    invoke-static {p0, v4}, Lcom/toolkitdev/security/RuntimeGuard;->readDerInt([BLcom/toolkitdev/security/RuntimeGuard$DerElement;)I

    move-result v4

    .line 472
    if-nez v3, :cond_6

    .line 473
    const-string p0, "Bootloader Unlocked terdeteksi langsung dari Hardware TEE Keystore"

    return-object p0

    .line 475
    :cond_6
    if-eqz v4, :cond_7

    .line 476
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    const-string p1, "Verified Boot tidak terverifikasi pada Hardware TEE (state="

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object p0

    const-string p1, ")"

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    .line 479
    :cond_7
    invoke-static {v6}, Lcom/toolkitdev/security/RuntimeGuard;->isAllZero([B)Z

    move-result v3

    if-eqz v3, :cond_8

    .line 480
    const-string p0, "Hardware Attestation dipalsukan (TrickyStore / verifiedBootKey kosong/nol)"

    return-object p0

    .line 483
    :cond_8
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v3

    const/4 v4, 0x4

    if-lt v3, v4, :cond_b

    .line 484
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    .line 485
    iget v3, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v4, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget p1, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v4, p1

    invoke-static {p0, v3, v4}, Ljava/util/Arrays;->copyOfRange([BII)[B

    move-result-object p1

    .line 486
    array-length v3, p1

    if-lez v3, :cond_9

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->isAllZero([B)Z

    move-result v3

    if-eqz v3, :cond_9

    .line 487
    const-string p0, "Hardware Attestation dipalsukan (TrickyStore / verifiedBootHash nol)"

    return-object p0

    .line 489
    :cond_9
    array-length v3, p1

    const/16 v4, 0x20

    if-ne v3, v4, :cond_b

    if-eqz p2, :cond_b

    .line 490
    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v3

    .line 491
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v4

    const/16 v5, 0x40

    if-ne v4, v5, :cond_b

    const-string v4, "0000000000000000000000000000000000000000000000000000000000000000"

    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_b

    .line 492
    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->toHexLower([B)Ljava/lang/String;

    move-result-object p1

    .line 493
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_b

    .line 494
    const-string p0, "Manipulasi Hardware Attestation terdeteksi (TrickyStore / vbmeta.digest tidak cocok dengan TEE)"

    return-object p0

    .line 455
    :cond_a
    :goto_3
    return-object v0

    .line 501
    :cond_b
    goto/16 :goto_0

    .line 502
    :cond_c
    :goto_4
    return-object v0

    .line 445
    :cond_d
    :goto_5
    return-object v0
.end method

.method public static install(Landroid/content/Context;)V
    .locals 1

    .line 912
    if-nez p0, :cond_0

    return-void

    .line 914
    :cond_0
    :try_start_0
    instance-of v0, p0, Landroid/app/Application;

    if-eqz v0, :cond_2

    .line 915
    sget-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sInstalled:Z

    if-nez v0, :cond_1

    .line 916
    const/4 v0, 0x1

    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sInstalled:Z

    .line 917
    check-cast p0, Landroid/app/Application;

    new-instance v0, Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;

    invoke-direct {v0}, Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;-><init>()V

    invoke-virtual {p0, v0}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 920
    :cond_1
    :try_start_1
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->checkHardwareKeyAttestation()Ljava/lang/String;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 921
    :goto_0
    goto :goto_1

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 922
    :goto_1
    return-void

    .line 924
    :cond_2
    :try_start_2
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    goto :goto_2

    .line 925
    :catchall_1
    move-exception p0

    :goto_2
    nop

    .line 926
    return-void
.end method

.method private static isAllZero([B)Z
    .locals 5

    .line 146
    const/4 v0, 0x1

    if-eqz p0, :cond_3

    array-length v1, p0

    if-nez v1, :cond_0

    goto :goto_1

    .line 147
    :cond_0
    array-length v1, p0

    const/4 v2, 0x0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v1, :cond_2

    aget-byte v4, p0, v3

    .line 148
    if-eqz v4, :cond_1

    return v2

    .line 147
    :cond_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    .line 150
    :cond_2
    return v0

    .line 146
    :cond_3
    :goto_1
    return v0
.end method

.method public static isDeviceRooted()Z
    .locals 11

    .line 156
    const-string v9, "/data/adb/ksu"

    const-string v10, "/data/adb/apatch"

    const-string v0, "/system/bin/su"

    const-string v1, "/system/xbin/su"

    const-string v2, "/sbin/su"

    const-string v3, "/vendor/bin/su"

    const-string v4, "/data/local/xbin/su"

    const-string v5, "/system/app/Superuser.apk"

    const-string v6, "/sbin/.magisk"

    const-string v7, "/debug_ramdisk/.magisk"

    const-string v8, "/data/adb/magisk"

    filled-new-array/range {v0 .. v10}, [Ljava/lang/String;

    move-result-object v0

    .line 169
    const/4 v1, 0x0

    const/4 v2, 0x0

    :goto_0
    const/4 v3, 0x1

    const/16 v4, 0xb

    if-ge v2, v4, :cond_1

    aget-object v4, v0, v2

    .line 170
    invoke-static {v4}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_0

    return v3

    .line 169
    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 173
    :cond_1
    sget-object v0, Landroid/os/Build;->TAGS:Ljava/lang/String;

    if-eqz v0, :cond_2

    sget-object v0, Landroid/os/Build;->TAGS:Ljava/lang/String;

    const-string v2, "test-keys"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 174
    return v3

    .line 177
    :cond_2
    nop

    .line 179
    const/4 v2, 0x0

    :try_start_0
    new-instance v4, Ljava/io/BufferedReader;

    new-instance v0, Ljava/io/FileReader;

    const-string v5, "/proc/self/mounts"

    invoke-direct {v0, v5}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v4, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 181
    :goto_1
    :try_start_1
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_5

    .line 182
    invoke-virtual {v0}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v0

    .line 183
    const-string v2, "magisk"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "kernelsu"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "apatch"

    .line 184
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "debug_ramdisk"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "core/mirror"

    .line 185
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "/data/adb/modules"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "shamiko"

    .line 186
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "susfs"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    if-eqz v0, :cond_3

    goto :goto_2

    .line 189
    :cond_3
    goto :goto_1

    .line 187
    :cond_4
    :goto_2
    nop

    .line 192
    nop

    .line 193
    :try_start_2
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception v0

    .line 187
    :goto_3
    return v3

    .line 192
    :cond_5
    nop

    .line 193
    :try_start_3
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V

    goto :goto_5

    :catchall_1
    move-exception v0

    goto :goto_5

    .line 190
    :catchall_2
    move-exception v0

    move-object v2, v4

    goto :goto_4

    :catchall_3
    move-exception v0

    .line 192
    :goto_4
    if-eqz v2, :cond_6

    .line 193
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 196
    :cond_6
    :goto_5
    return v1
.end method

.method public static isEmulatorDetected()Z
    .locals 6

    .line 624
    const-string v0, "/dev/qemu_pipe"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v0

    const/4 v1, 0x1

    if-nez v0, :cond_7

    const-string v0, "/dev/socket/qemud"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_0

    .line 625
    :cond_0
    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    const-string v2, "sdk_gphone"

    const-string v3, "ranchu"

    const-string v4, "goldfish"

    if-eqz v0, :cond_2

    .line 626
    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v0

    .line 627
    invoke-virtual {v0, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_1

    invoke-virtual {v0, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_1

    const-string v5, "qemu"

    invoke-virtual {v0, v5}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_1

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 628
    :cond_1
    return v1

    .line 631
    :cond_2
    sget-object v0, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    if-eqz v0, :cond_4

    .line 632
    sget-object v0, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v0

    .line 633
    invoke-virtual {v0, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v4

    if-nez v4, :cond_3

    invoke-virtual {v0, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_3

    const-string v3, "vbox86p"

    invoke-virtual {v0, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_3

    const-string v3, "nox"

    invoke-virtual {v0, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_4

    .line 634
    :cond_3
    return v1

    .line 637
    :cond_4
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    if-eqz v0, :cond_6

    .line 638
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v0

    .line 639
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_5

    const-string v2, "genymotion"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_5

    const-string v2, "bluestacks"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_5

    const-string v2, "ldplayer"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_6

    .line 640
    :cond_5
    return v1

    .line 643
    :cond_6
    const/4 v0, 0x0

    return v0

    .line 624
    :cond_7
    :goto_0
    return v1
.end method

.method public static isHookFrameworkDetected()Z
    .locals 9

    .line 550
    const-string v0, "substrate"

    const-string v1, "lsposed"

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isPureJavaMethodHooked()Z

    move-result v2

    const/4 v3, 0x1

    if-eqz v2, :cond_0

    return v3

    .line 553
    :cond_0
    const/4 v2, 0x0

    :try_start_0
    new-instance v4, Ljava/lang/Throwable;

    invoke-direct {v4}, Ljava/lang/Throwable;-><init>()V

    invoke-virtual {v4}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    move-result-object v4

    .line 554
    if-eqz v4, :cond_3

    .line 555
    array-length v5, v4

    const/4 v6, 0x0

    :goto_0
    if-ge v6, v5, :cond_3

    aget-object v7, v4, v6

    .line 556
    invoke-virtual {v7}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    move-result-object v7

    .line 557
    if-eqz v7, :cond_2

    .line 558
    invoke-virtual {v7}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v7

    .line 559
    const-string v8, "xposed"

    invoke-virtual {v7, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_1

    invoke-virtual {v7, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_1

    const-string v8, "lsphooker"

    .line 560
    invoke-virtual {v7, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_1

    const-string v8, "edhooker"

    invoke-virtual {v7, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_1

    .line 561
    invoke-virtual {v7, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_1

    const-string v8, "frida"

    invoke-virtual {v7, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v7, :cond_2

    .line 562
    :cond_1
    return v3

    .line 555
    :cond_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    .line 567
    :catchall_0
    move-exception v4

    :cond_3
    nop

    .line 569
    nop

    .line 571
    const/4 v4, 0x0

    :try_start_1
    new-instance v5, Ljava/io/BufferedReader;

    new-instance v6, Ljava/io/FileReader;

    const-string v7, "/proc/self/maps"

    invoke-direct {v6, v7}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v5, v6}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 573
    :goto_1
    :try_start_2
    invoke-virtual {v5}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_6

    .line 574
    invoke-virtual {v6}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v6

    .line 575
    const-string v7, "frida-agent"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "frida-server"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "gumjs"

    .line 576
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "libfrida"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "libzygisk"

    .line 577
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    invoke-virtual {v6, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "lsplant"

    .line 578
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "edxposed"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "riru"

    .line 579
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    invoke-virtual {v6, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "libgadget"

    .line 580
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "shamiko"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "devoptshide"

    .line 581
    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_5

    const-string v7, "hidemyapplist"

    invoke-virtual {v6, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    if-eqz v6, :cond_4

    goto :goto_2

    .line 584
    :cond_4
    goto :goto_1

    .line 582
    :cond_5
    :goto_2
    nop

    .line 587
    nop

    .line 588
    :try_start_3
    invoke-virtual {v5}, Ljava/io/BufferedReader;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception v0

    .line 582
    :goto_3
    return v3

    .line 587
    :cond_6
    nop

    .line 588
    :try_start_4
    invoke-virtual {v5}, Ljava/io/BufferedReader;->close()V

    goto :goto_5

    :catchall_2
    move-exception v0

    goto :goto_5

    .line 585
    :catchall_3
    move-exception v0

    goto :goto_4

    :catchall_4
    move-exception v0

    move-object v5, v4

    .line 587
    :goto_4
    if-eqz v5, :cond_7

    .line 588
    invoke-virtual {v5}, Ljava/io/BufferedReader;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 592
    :cond_7
    :goto_5
    nop

    .line 594
    :try_start_5
    new-instance v0, Ljava/io/BufferedReader;

    new-instance v1, Ljava/io/FileReader;

    const-string v5, "/proc/net/tcp"

    invoke-direct {v1, v5}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_8

    .line 596
    :cond_8
    :try_start_6
    invoke-virtual {v0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_a

    .line 597
    const-string v4, ":69A2"

    invoke-virtual {v1, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v4

    if-nez v4, :cond_9

    const-string v4, "27042"

    invoke-virtual {v1, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_7

    if-eqz v1, :cond_8

    .line 598
    :cond_9
    nop

    .line 603
    nop

    .line 604
    :try_start_7
    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    goto :goto_6

    :catchall_5
    move-exception v0

    .line 598
    :goto_6
    return v3

    .line 603
    :cond_a
    nop

    .line 604
    :try_start_8
    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V

    goto :goto_8

    :catchall_6
    move-exception v0

    goto :goto_8

    .line 601
    :catchall_7
    move-exception v1

    move-object v4, v0

    goto :goto_7

    :catchall_8
    move-exception v0

    .line 603
    :goto_7
    if-eqz v4, :cond_b

    .line 604
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    .line 608
    :cond_b
    :goto_8
    const-string v0, "org.lsposed.lspd.core.Main"

    const-string v1, "com.saurik.substrate.MS$2"

    const-string v4, "de.robv.android.xposed.XposedBridge"

    const-string v5, "de.robv.android.xposed.XC_MethodHook"

    filled-new-array {v4, v5, v0, v1}, [Ljava/lang/String;

    move-result-object v0

    .line 614
    const/4 v1, 0x0

    :goto_9
    const/4 v4, 0x4

    if-ge v1, v4, :cond_c

    aget-object v4, v0, v1

    .line 616
    :try_start_9
    invoke-static {v4}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_9

    .line 617
    return v3

    .line 618
    :catchall_9
    move-exception v4

    .line 614
    add-int/lit8 v1, v1, 0x1

    goto :goto_9

    .line 620
    :cond_c
    return v2
.end method

.method public static isMagiskOrRootAppInstalled(Landroid/content/Context;)Z
    .locals 30

    .line 200
    const-string v28, "com.dimonvideo.luckypatcher"

    const-string v29, "net.jolivier.cert.Importer"

    const-string v2, "com.topjohnwu.magisk"

    const-string v3, "io.github.vvb2060.magisk"

    const-string v4, "io.github.huskydg.magisk"

    const-string v5, "com.topjohnwu.magisk.alpha"

    const-string v6, "me.weishu.kernelsu"

    const-string v7, "com.rifsxd.ksunext"

    const-string v8, "com.sukisu.ultra"

    const-string v9, "io.github.a13e300.ksuwebui"

    const-string v10, "me.bmax.apatch"

    const-string v11, "org.lsposed.manager"

    const-string v12, "io.github.lsposed.manager"

    const-string v13, "org.meowcat.edxposed.manager"

    const-string v14, "de.robv.android.xposed.installer"

    const-string v15, "com.solohsu.android.edxp.manager"

    const-string v16, "net.accelf.devoptshide"

    const-string v17, "com.accelforce.devoptshide"

    const-string v18, "com.tsng.hidemyapplist"

    const-string v19, "com.google.android.hmal"

    const-string v20, "icu.nullptr.hidemyapplist"

    const-string v21, "io.github.chankyin.bootloaderspoofer"

    const-string v22, "eu.chainfire.supersu"

    const-string v23, "com.koushikdutta.superuser"

    const-string v24, "com.noshufou.android.su"

    const-string v25, "com.thirdparty.superuser"

    const-string v26, "ru.aaaaaccg.installer"

    const-string v27, "com.chelpus.lackypatch"

    filled-new-array/range {v2 .. v29}, [Ljava/lang/String;

    move-result-object v0

    .line 230
    const/4 v1, 0x0

    const/4 v2, 0x0

    :goto_0
    const/4 v3, 0x1

    const/16 v4, 0x1c

    if-ge v2, v4, :cond_1

    aget-object v4, v0, v2

    .line 231
    move-object/from16 v5, p0

    invoke-static {v5, v4}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_0

    return v3

    .line 230
    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 234
    :cond_1
    const-string v0, "ro.boot.verifiedbootstate"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 235
    const-string v2, "orange"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v2

    if-nez v2, :cond_9

    const-string v2, "yellow"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v2

    if-nez v2, :cond_9

    const-string v2, "red"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_2

    goto/16 :goto_5

    .line 238
    :cond_2
    const-string v0, "ro.boot.flash.locked"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "0"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    return v3

    .line 239
    :cond_3
    const-string v0, "ro.boot.vbmeta.device_state"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "unlocked"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_4

    return v3

    .line 240
    :cond_4
    const-string v0, "ro.boot.warranty_bit"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "1"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8

    const-string v0, "ro.warranty_bit"

    invoke-static {v0}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_5

    goto :goto_4

    .line 242
    :cond_5
    nop

    .line 244
    const/4 v2, 0x0

    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const-string v4, "which su"

    invoke-virtual {v0, v4}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v0

    .line 245
    new-instance v4, Ljava/io/BufferedReader;

    new-instance v5, Ljava/io/InputStreamReader;

    invoke-virtual {v0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object v0

    invoke-direct {v5, v0}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v4, v5}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 246
    :try_start_1
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0

    .line 247
    if-eqz v0, :cond_6

    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    if-lez v0, :cond_6

    .line 250
    nop

    .line 251
    :try_start_2
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v0

    .line 247
    :goto_1
    return v3

    .line 250
    :cond_6
    nop

    .line 251
    :try_start_3
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V

    goto :goto_3

    :catchall_1
    move-exception v0

    goto :goto_3

    .line 248
    :catchall_2
    move-exception v0

    move-object v2, v4

    goto :goto_2

    :catchall_3
    move-exception v0

    .line 250
    :goto_2
    if-eqz v2, :cond_7

    .line 251
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 254
    :cond_7
    :goto_3
    return v1

    .line 240
    :cond_8
    :goto_4
    return v3

    .line 236
    :cond_9
    :goto_5
    return v3
.end method

.method private static isPureJavaMethodHooked()Z
    .locals 9

    .line 509
    const-string v0, "getString"

    const-string v1, "getInt"

    const/4 v2, 0x3

    const/4 v3, 0x2

    const/4 v4, 0x0

    const/4 v5, 0x1

    :try_start_0
    const-class v6, Landroid/provider/Settings$Global;

    new-array v7, v2, [Ljava/lang/Class;

    const-class v8, Landroid/content/ContentResolver;

    aput-object v8, v7, v4

    const-class v8, Ljava/lang/String;

    aput-object v8, v7, v5

    sget-object v8, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    aput-object v8, v7, v3

    invoke-virtual {v6, v1, v7}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    .line 511
    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v6, :cond_0

    return v5

    .line 512
    :catchall_0
    move-exception v6

    :cond_0
    nop

    .line 514
    :try_start_1
    const-class v6, Landroid/provider/Settings$Global;

    new-array v7, v3, [Ljava/lang/Class;

    const-class v8, Landroid/content/ContentResolver;

    aput-object v8, v7, v4

    const-class v8, Ljava/lang/String;

    aput-object v8, v7, v5

    invoke-virtual {v6, v1, v7}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    .line 516
    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v6, :cond_1

    return v5

    .line 517
    :catchall_1
    move-exception v6

    :cond_1
    nop

    .line 519
    :try_start_2
    const-class v6, Landroid/provider/Settings$Global;

    new-array v7, v3, [Ljava/lang/Class;

    const-class v8, Landroid/content/ContentResolver;

    aput-object v8, v7, v4

    const-class v8, Ljava/lang/String;

    aput-object v8, v7, v5

    invoke-virtual {v6, v0, v7}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    .line 521
    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-eqz v6, :cond_2

    return v5

    .line 522
    :catchall_2
    move-exception v6

    :cond_2
    nop

    .line 524
    :try_start_3
    const-class v6, Landroid/provider/Settings$Secure;

    new-array v2, v2, [Ljava/lang/Class;

    const-class v7, Landroid/content/ContentResolver;

    aput-object v7, v2, v4

    const-class v7, Ljava/lang/String;

    aput-object v7, v2, v5

    sget-object v7, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    aput-object v7, v2, v3

    invoke-virtual {v6, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    .line 526
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v1

    invoke-static {v1}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    if-eqz v1, :cond_3

    return v5

    .line 527
    :catchall_3
    move-exception v1

    :cond_3
    nop

    .line 529
    :try_start_4
    const-class v1, Landroid/provider/Settings$Secure;

    new-array v2, v3, [Ljava/lang/Class;

    const-class v6, Landroid/content/ContentResolver;

    aput-object v6, v2, v4

    const-class v6, Ljava/lang/String;

    aput-object v6, v2, v5

    invoke-virtual {v1, v0, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    .line 531
    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    if-eqz v0, :cond_4

    return v5

    .line 532
    :catchall_4
    move-exception v0

    :cond_4
    nop

    .line 534
    :try_start_5
    const-class v0, Ljava/io/File;

    const-string v1, "exists"

    new-array v2, v4, [Ljava/lang/Class;

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    .line 535
    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    if-eqz v0, :cond_5

    return v5

    .line 536
    :catchall_5
    move-exception v0

    :cond_5
    nop

    .line 538
    :try_start_6
    const-class v0, Ljava/lang/Runtime;

    const-string v1, "exec"

    new-array v2, v5, [Ljava/lang/Class;

    const-class v6, Ljava/lang/String;

    aput-object v6, v2, v4

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    .line 539
    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    if-eqz v0, :cond_6

    return v5

    .line 540
    :catchall_6
    move-exception v0

    :cond_6
    nop

    .line 542
    :try_start_7
    const-string v0, "android.app.ApplicationPackageManager"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    .line 543
    const-string v1, "getPackageInfo"

    new-array v2, v3, [Ljava/lang/Class;

    const-class v3, Ljava/lang/String;

    aput-object v3, v2, v4

    sget-object v3, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    aput-object v3, v2, v5

    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    .line 544
    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isNative(I)Z

    move-result v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    if-eqz v0, :cond_7

    return v5

    .line 545
    :catchall_7
    move-exception v0

    :cond_7
    nop

    .line 546
    return v4
.end method

.method public static isTracerOrDebuggerAttached()Z
    .locals 5

    .line 647
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z

    move-result v0

    const/4 v1, 0x1

    if-nez v0, :cond_4

    invoke-static {}, Landroid/os/Debug;->waitingForDebugger()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_3

    .line 648
    :cond_0
    nop

    .line 650
    const/4 v0, 0x0

    :try_start_0
    new-instance v2, Ljava/io/BufferedReader;

    new-instance v3, Ljava/io/FileReader;

    const-string v4, "/proc/self/status"

    invoke-direct {v3, v4}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v2, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 652
    :cond_1
    :try_start_1
    invoke-virtual {v2}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_2

    .line 653
    const-string v3, "TracerPid:"

    invoke-virtual {v0, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_1

    .line 654
    const/16 v3, 0xa

    invoke-virtual {v0, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    .line 655
    const-string v3, "0"

    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    if-nez v0, :cond_2

    .line 661
    nop

    .line 662
    :try_start_2
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    .line 655
    :goto_0
    return v1

    .line 661
    :cond_2
    nop

    .line 662
    :try_start_3
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V

    goto :goto_2

    :catchall_1
    move-exception v0

    goto :goto_2

    .line 659
    :catchall_2
    move-exception v0

    move-object v0, v2

    goto :goto_1

    :catchall_3
    move-exception v1

    .line 661
    :goto_1
    if-eqz v0, :cond_3

    .line 662
    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 665
    :cond_3
    :goto_2
    const/4 v0, 0x0

    return v0

    .line 647
    :cond_4
    :goto_3
    return v1
.end method

.method private static lockActivitySurface(Landroid/app/Activity;Ljava/lang/String;)V
    .locals 8

    .line 772
    :try_start_0
    new-instance v0, Landroid/widget/FrameLayout;

    invoke-direct {v0, p0}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V

    .line 773
    const-string v1, "#0B1120"

    invoke-static {v1}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result v1

    invoke-virtual {v0, v1}, Landroid/widget/FrameLayout;->setBackgroundColor(I)V

    .line 774
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/widget/FrameLayout;->setClickable(Z)V

    .line 775
    invoke-virtual {v0, v1}, Landroid/widget/FrameLayout;->setFocusable(Z)V

    .line 776
    new-instance v2, Landroid/view/ViewGroup$LayoutParams;

    const/4 v3, -0x1

    invoke-direct {v2, v3, v3}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    invoke-virtual {v0, v2}, Landroid/widget/FrameLayout;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 780
    new-instance v2, Landroid/widget/LinearLayout;

    invoke-direct {v2, p0}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V

    .line 781
    invoke-virtual {v2, v1}, Landroid/widget/LinearLayout;->setOrientation(I)V

    .line 782
    const/16 v1, 0x11

    invoke-virtual {v2, v1}, Landroid/widget/LinearLayout;->setGravity(I)V

    .line 783
    const/16 v4, 0x40

    invoke-virtual {v2, v4, v4, v4, v4}, Landroid/widget/LinearLayout;->setPadding(IIII)V

    .line 785
    new-instance v4, Landroid/widget/TextView;

    invoke-direct {v4, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V

    .line 786
    const-string v5, "\u26a0\ufe0f AKSES & TRANSAKSI DIBLOKIR"

    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 787
    const-string v5, "#EF4444"

    invoke-static {v5}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result v5

    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setTextColor(I)V

    .line 788
    const/high16 v5, 0x41900000    # 18.0f

    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setTextSize(F)V

    .line 789
    invoke-virtual {v4, v1}, Landroid/widget/TextView;->setGravity(I)V

    .line 791
    new-instance v5, Landroid/widget/TextView;

    invoke-direct {v5, p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V

    .line 792
    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "\nPerangkat terdeteksi tidak aman:\n\n\u2022 "

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v6, "\n\nDemi keamanan akun & transaksi, aplikasi ditutup otomatis."

    invoke-virtual {p1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v5, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 794
    const-string p1, "#E2E8F0"

    invoke-static {p1}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    move-result p1

    invoke-virtual {v5, p1}, Landroid/widget/TextView;->setTextColor(I)V

    .line 795
    const/high16 p1, 0x41600000    # 14.0f

    invoke-virtual {v5, p1}, Landroid/widget/TextView;->setTextSize(F)V

    .line 796
    invoke-virtual {v5, v1}, Landroid/widget/TextView;->setGravity(I)V

    .line 798
    invoke-virtual {v2, v4}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V

    .line 799
    invoke-virtual {v2, v5}, Landroid/widget/LinearLayout;->addView(Landroid/view/View;)V

    .line 800
    new-instance p1, Landroid/widget/FrameLayout$LayoutParams;

    invoke-direct {p1, v3, v3}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    invoke-virtual {v0, v2, p1}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 804
    invoke-virtual {p0, v0}, Landroid/app/Activity;->setContentView(Landroid/view/View;)V

    .line 805
    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/app/Activity;->setFinishOnTouchOutside(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    .line 806
    :catchall_0
    move-exception p0

    :goto_0
    nop

    .line 807
    return-void
.end method

.method private static native nativeGetProp(Ljava/lang/String;)Ljava/lang/String;
.end method

.method private static native nativeHardTerminate()V
.end method

.method private static native nativeScan()I
.end method

.method private static native nativeScanDetails()Ljava/lang/String;
.end method

.method static parseKeyAttestationExtension([B[BLjava/lang/String;I)Ljava/lang/String;
    .locals 7

    .line 401
    const/4 v0, 0x0

    array-length v1, p0

    invoke-static {p0, v0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object v0

    .line 402
    const/4 v1, 0x0

    if-eqz v0, :cond_b

    iget v2, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagNumber:I

    const/4 v3, 0x4

    if-eq v2, v3, :cond_0

    goto/16 :goto_3

    .line 404
    :cond_0
    iget v2, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v4, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v0, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v4, v0

    invoke-static {p0, v2, v4}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object v0

    .line 405
    if-eqz v0, :cond_a

    iget-boolean v2, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->constructed:Z

    if-eqz v2, :cond_a

    iget v2, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagNumber:I

    const/16 v4, 0x10

    if-eq v2, v4, :cond_1

    goto/16 :goto_2

    .line 407
    :cond_1
    iget v2, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    .line 408
    iget v4, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v0, v0, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v4, v0

    .line 409
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 410
    :goto_0
    if-ge v2, v4, :cond_3

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v5

    const/16 v6, 0xa

    if-ge v5, v6, :cond_3

    .line 411
    invoke-static {p0, v2, v4}, Lcom/toolkitdev/security/RuntimeGuard;->readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    move-result-object v2

    .line 412
    if-nez v2, :cond_2

    goto :goto_1

    .line 413
    :cond_2
    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 414
    iget v2, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->nextPos:I

    .line 415
    goto :goto_0

    .line 416
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v2

    const/16 v4, 0x8

    if-ge v2, v4, :cond_4

    return-object v1

    .line 419
    :cond_4
    const/4 v2, 0x1

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    invoke-static {p0, v2}, Lcom/toolkitdev/security/RuntimeGuard;->readDerInt([BLcom/toolkitdev/security/RuntimeGuard$DerElement;)I

    move-result v2

    .line 420
    if-nez v2, :cond_5

    const/16 v2, 0x1d

    if-lt p3, v2, :cond_5

    .line 421
    const-string p0, "Software-Only Key Attestation terdeteksi (TEE dibypass / Fake Keybox)"

    return-object p0

    .line 425
    :cond_5
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    .line 426
    iget v2, p3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    array-length v3, p1

    if-eq v2, v3, :cond_6

    .line 427
    const-string p0, "Challenge Hardware Attestation tidak cocok (Spoofing terdeteksi)"

    return-object p0

    .line 429
    :cond_6
    iget v2, p3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget v3, p3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    iget p3, p3, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    add-int/2addr v3, p3

    invoke-static {p0, v2, v3}, Ljava/util/Arrays;->copyOfRange([BII)[B

    move-result-object p3

    .line 430
    invoke-static {p3, p1}, Ljava/util/Arrays;->equals([B[B)Z

    move-result p1

    if-nez p1, :cond_7

    .line 431
    const-string p0, "Challenge Hardware Attestation dimanipulasi (Spoofing terdeteksi)"

    return-object p0

    .line 435
    :cond_7
    const/4 p1, 0x7

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    invoke-static {p0, p1, p2}, Lcom/toolkitdev/security/RuntimeGuard;->inspectAuthorizationListForRootOfTrust([BLcom/toolkitdev/security/RuntimeGuard$DerElement;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 436
    if-eqz p1, :cond_8

    return-object p1

    .line 438
    :cond_8
    const/4 p1, 0x6

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    invoke-static {p0, p1, p2}, Lcom/toolkitdev/security/RuntimeGuard;->inspectAuthorizationListForRootOfTrust([BLcom/toolkitdev/security/RuntimeGuard$DerElement;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 439
    if-eqz p0, :cond_9

    return-object p0

    .line 441
    :cond_9
    return-object v1

    .line 405
    :cond_a
    :goto_2
    return-object v1

    .line 402
    :cond_b
    :goto_3
    return-object v1
.end method

.method private static readDer([BII)Lcom/toolkitdev/security/RuntimeGuard$DerElement;
    .locals 7

    .line 355
    const/4 v0, 0x0

    if-lt p1, p2, :cond_0

    return-object v0

    .line 356
    :cond_0
    add-int/lit8 v1, p1, 0x1

    aget-byte p1, p0, p1

    and-int/lit16 p1, p1, 0xff

    .line 357
    new-instance v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;

    invoke-direct {v2, v0}, Lcom/toolkitdev/security/RuntimeGuard$DerElement;-><init>(Lcom/toolkitdev/security/RuntimeGuard$1;)V

    .line 358
    shr-int/lit8 v3, p1, 0x6

    and-int/lit8 v3, v3, 0x3

    iput v3, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagClass:I

    .line 359
    and-int/lit8 v3, p1, 0x20

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    const/4 v3, 0x1

    goto :goto_0

    :cond_1
    const/4 v3, 0x0

    :goto_0
    iput-boolean v3, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->constructed:Z

    .line 360
    const/16 v3, 0x1f

    and-int/2addr p1, v3

    .line 361
    if-ne p1, v3, :cond_3

    .line 362
    nop

    .line 363
    const/4 p1, 0x0

    const/4 v3, 0x0

    .line 364
    :goto_1
    if-ge v1, p2, :cond_3

    add-int/lit8 v5, v3, 0x1

    const/4 v6, 0x5

    if-ge v3, v6, :cond_3

    .line 365
    add-int/lit8 v3, v1, 0x1

    aget-byte v1, p0, v1

    and-int/lit16 v1, v1, 0xff

    .line 366
    shl-int/lit8 p1, p1, 0x7

    and-int/lit8 v6, v1, 0x7f

    or-int/2addr p1, v6

    .line 367
    and-int/lit16 v1, v1, 0x80

    if-nez v1, :cond_2

    move v1, v3

    goto :goto_2

    .line 368
    :cond_2
    move v1, v3

    move v3, v5

    goto :goto_1

    .line 370
    :cond_3
    :goto_2
    iput p1, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->tagNumber:I

    .line 371
    if-lt v1, p2, :cond_4

    return-object v0

    .line 373
    :cond_4
    add-int/lit8 p1, v1, 0x1

    aget-byte v1, p0, v1

    and-int/lit16 v1, v1, 0xff

    .line 375
    and-int/lit16 v3, v1, 0x80

    if-nez v3, :cond_5

    .line 376
    goto :goto_4

    .line 378
    :cond_5
    and-int/lit8 v1, v1, 0x7f

    .line 379
    if-eqz v1, :cond_a

    const/4 v3, 0x4

    if-gt v1, v3, :cond_a

    add-int v3, p1, v1

    if-le v3, p2, :cond_6

    goto :goto_6

    .line 380
    :cond_6
    nop

    .line 381
    const/4 v3, 0x0

    :goto_3
    if-ge v4, v1, :cond_7

    .line 382
    shl-int/lit8 v3, v3, 0x8

    add-int/lit8 v5, p1, 0x1

    aget-byte p1, p0, p1

    and-int/lit16 p1, p1, 0xff

    or-int/2addr v3, p1

    .line 381
    add-int/lit8 v4, v4, 0x1

    move p1, v5

    goto :goto_3

    :cond_7
    move v1, v3

    .line 385
    :goto_4
    if-ltz v1, :cond_9

    add-int p0, p1, v1

    if-le p0, p2, :cond_8

    goto :goto_5

    .line 386
    :cond_8
    iput p1, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    .line 387
    iput v1, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    .line 388
    iput p0, v2, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->nextPos:I

    .line 389
    return-object v2

    .line 385
    :cond_9
    :goto_5
    return-object v0

    .line 379
    :cond_a
    :goto_6
    return-object v0
.end method

.method private static readDerInt([BLcom/toolkitdev/security/RuntimeGuard$DerElement;)I
    .locals 3

    .line 393
    nop

    .line 394
    const/4 v0, 0x0

    const/4 v1, 0x0

    :goto_0
    iget v2, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valLen:I

    if-ge v0, v2, :cond_0

    .line 395
    shl-int/lit8 v1, v1, 0x8

    iget v2, p1, Lcom/toolkitdev/security/RuntimeGuard$DerElement;->valStart:I

    add-int/2addr v2, v0

    aget-byte v2, p0, v2

    and-int/lit16 v2, v2, 0xff

    or-int/2addr v1, v2

    .line 394
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 397
    :cond_0
    return v1
.end method

.method private static scheduleFailsafeKill(Landroid/app/Activity;)V
    .locals 5

    .line 810
    sget-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sKillScheduled:Z

    if-eqz v0, :cond_0

    return-void

    .line 811
    :cond_0
    const/4 v0, 0x1

    sput-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sKillScheduled:Z

    .line 813
    :try_start_0
    new-instance v1, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v2, Lcom/toolkitdev/security/RuntimeGuard$1;

    invoke-direct {v2, p0}, Lcom/toolkitdev/security/RuntimeGuard$1;-><init>(Landroid/app/Activity;)V

    const-wide/16 v3, 0x1770

    invoke-virtual {v1, v2, v3, v4}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    .line 819
    :catchall_0
    move-exception p0

    :goto_0
    nop

    .line 822
    :try_start_1
    new-instance p0, Ljava/lang/Thread;

    new-instance v1, Lcom/toolkitdev/security/RuntimeGuard$2;

    invoke-direct {v1}, Lcom/toolkitdev/security/RuntimeGuard$2;-><init>()V

    invoke-direct {p0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 829
    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 830
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_1

    .line 831
    :catchall_1
    move-exception p0

    :goto_1
    nop

    .line 832
    return-void
.end method

.method private static terminateActivityAndApp(Landroid/app/Activity;)V
    .locals 1

    .line 760
    if-eqz p0, :cond_0

    .line 762
    :try_start_0
    invoke-virtual {p0}, Landroid/app/Activity;->finishAffinity()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 765
    goto :goto_0

    .line 763
    :catchall_0
    move-exception v0

    .line 764
    :try_start_1
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p0

    .line 767
    :cond_0
    :goto_0
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->terminateApp()V

    .line 768
    return-void
.end method

.method public static terminateApp()V
    .locals 2

    .line 744
    :try_start_0
    sget-boolean v0, Lcom/toolkitdev/security/RuntimeGuard;->sNativeLoaded:Z

    if-eqz v0, :cond_0

    .line 745
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->nativeHardTerminate()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    .line 747
    :catchall_0
    move-exception v0

    :cond_0
    :goto_0
    nop

    .line 749
    :try_start_1
    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_1

    .line 750
    :catchall_1
    move-exception v0

    :goto_1
    nop

    .line 752
    const/4 v0, 0x1

    :try_start_2
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/Runtime;->halt(I)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    goto :goto_2

    .line 753
    :catchall_2
    move-exception v1

    :goto_2
    nop

    .line 755
    :try_start_3
    invoke-static {v0}, Ljava/lang/System;->exit(I)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 756
    :goto_3
    goto :goto_4

    :catchall_3
    move-exception v0

    goto :goto_3

    .line 757
    :goto_4
    return-void
.end method

.method private static toHexLower([B)Ljava/lang/String;
    .locals 6

    .line 134
    if-nez p0, :cond_0

    const-string p0, ""

    return-object p0

    .line 135
    :cond_0
    const-string v0, "0123456789abcdef"

    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    move-result-object v0

    .line 136
    array-length v1, p0

    mul-int/lit8 v1, v1, 0x2

    new-array v1, v1, [C

    .line 137
    const/4 v2, 0x0

    :goto_0
    array-length v3, p0

    if-ge v2, v3, :cond_1

    .line 138
    aget-byte v3, p0, v2

    and-int/lit16 v3, v3, 0xff

    .line 139
    mul-int/lit8 v4, v2, 0x2

    ushr-int/lit8 v5, v3, 0x4

    aget-char v5, v0, v5

    aput-char v5, v1, v4

    .line 140
    add-int/lit8 v4, v4, 0x1

    and-int/lit8 v3, v3, 0xf

    aget-char v3, v0, v3

    aput-char v3, v1, v4

    .line 137
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 142
    :cond_1
    new-instance p0, Ljava/lang/String;

    invoke-direct {p0, v1}, Ljava/lang/String;-><init>([C)V

    return-object p0
.end method
