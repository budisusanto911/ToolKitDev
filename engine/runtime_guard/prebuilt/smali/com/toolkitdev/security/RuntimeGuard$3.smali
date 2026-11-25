.class Lcom/toolkitdev/security/RuntimeGuard$3;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/content/DialogInterface$OnCancelListener;


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

    .line 873
    iput-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$3;->val$activity:Landroid/app/Activity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onCancel(Landroid/content/DialogInterface;)V
    .locals 0

    .line 876
    iget-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$3;->val$activity:Landroid/app/Activity;

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->access$100(Landroid/app/Activity;)V

    .line 877
    return-void
.end method
