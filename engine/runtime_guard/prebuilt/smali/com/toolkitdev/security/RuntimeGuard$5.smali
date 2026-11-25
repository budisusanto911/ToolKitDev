.class Lcom/toolkitdev/security/RuntimeGuard$5;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/content/DialogInterface$OnKeyListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic val$activity:Landroid/app/Activity;


# direct methods
.method constructor <init>(Landroid/app/Activity;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 885
    iput-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$5;->val$activity:Landroid/app/Activity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onKey(Landroid/content/DialogInterface;ILandroid/view/KeyEvent;)Z
    .locals 0

    .line 888
    const/4 p1, 0x4

    if-eq p2, p1, :cond_1

    const/16 p1, 0x54

    if-ne p2, p1, :cond_0

    goto :goto_0

    .line 892
    :cond_0
    const/4 p1, 0x0

    return p1

    .line 889
    :cond_1
    :goto_0
    iget-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$5;->val$activity:Landroid/app/Activity;

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->access$100(Landroid/app/Activity;)V

    .line 890
    const/4 p1, 0x1

    return p1
.end method
