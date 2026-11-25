.class public final Lcom/toolkitdev/security/RuntimeGuard$ExitListener;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/toolkitdev/security/RuntimeGuard;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ExitListener"
.end annotation


# instance fields
.field private final mActivity:Landroid/app/Activity;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 931
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 932
    const/4 v0, 0x0

    iput-object v0, p0, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;->mActivity:Landroid/app/Activity;

    .line 933
    return-void
.end method

.method public constructor <init>(Landroid/app/Activity;)V
    .locals 0

    .line 935
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 936
    iput-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;->mActivity:Landroid/app/Activity;

    .line 937
    return-void
.end method


# virtual methods
.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 0

    .line 941
    iget-object p1, p0, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;->mActivity:Landroid/app/Activity;

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->access$100(Landroid/app/Activity;)V

    .line 942
    return-void
.end method
