.class final Lcom/toolkitdev/security/RuntimeGuard$DerElement;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/toolkitdev/security/RuntimeGuard;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1a
    name = "DerElement"
.end annotation


# instance fields
.field constructed:Z

.field nextPos:I

.field tagClass:I

.field tagNumber:I

.field valLen:I

.field valStart:I


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 345
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method synthetic constructor <init>(Lcom/toolkitdev/security/RuntimeGuard$1;)V
    .locals 0

    .line 345
    invoke-direct {p0}, Lcom/toolkitdev/security/RuntimeGuard$DerElement;-><init>()V

    return-void
.end method
