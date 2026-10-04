package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"

	authpb "jitosearcher/pb/auth"
	bundlepb "jitosearcher/pb/bundle"
	packetpb "jitosearcher/pb/packet"
	searcherpb "jitosearcher/pb/searcher"
)

const bundleCap = 5 // jito caps a bundle at 5 txs total, tip included

type tokAuth struct {
	mu  sync.RWMutex
	tok string
}

func (t *tokAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.tok == "" {
		return nil, nil
	}
	return map[string]string{"authorization": "Bearer " + t.tok}, nil
}

func (t *tokAuth) RequireTransportSecurity() bool { return true }

func (t *tokAuth) set(tok string) {
	t.mu.Lock()
	t.tok = tok
	t.mu.Unlock()
}

type stats struct {
	submitted uint64
	landed    uint64
	dropped   uint64
	rejected  uint64
}

func (s *stats) snapshot() (submitted, landed, dropped, rejected uint64) {
	return atomic.LoadUint64(&s.submitted), atomic.LoadUint64(&s.landed),
		atomic.LoadUint64(&s.dropped), atomic.LoadUint64(&s.rejected)
}

type client struct {
	conn      *grpc.ClientConn
	auth      authpb.AuthServiceClient
	searcher  searcherpb.SearcherServiceClient
	rpcClient *rpc.Client
	kp        solana.PrivateKey
	tok       *tokAuth

	refreshTok string

	tipMu       sync.RWMutex
	tipAccounts []solana.PublicKey

	stats stats
}

// newClient dials the block engine and authenticates.
func newClient(ctx context.Context, blockEngineAddr, rpcEndpoint string, kp solana.PrivateKey) (*client, error) {
	tok := &tokAuth{}
	conn, err := grpc.NewClient(blockEngineAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(tok),
	)
	if err != nil {
		return nil, fmt.Errorf("jito: dial: %w", err)
	}

	c := &client{
		conn:      conn,
		auth:      authpb.NewAuthServiceClient(conn),
		searcher:  searcherpb.NewSearcherServiceClient(conn),
		rpcClient: rpc.New(rpcEndpoint),
		kp:        kp,
		tok:       tok,
	}

	if err := c.authenticate(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("jito: auth: %w", err)
	}

	return c, nil
}

func (c *client) authenticate(ctx context.Context) error {
	res, err := c.auth.GenerateAuthChallenge(ctx, &authpb.GenerateAuthChallengeRequest{
		Role:   authpb.Role_SEARCHER,
		Pubkey: c.kp.PublicKey().Bytes(),
	})
	if err != nil {
		return fmt.Errorf("jito: challenge: %w", err)
	}

	msg := fmt.Sprintf("%s-%s", c.kp.PublicKey().String(), res.Challenge)
	sig, err := c.kp.Sign([]byte(msg))
	if err != nil {
		return fmt.Errorf("jito: sign: %w", err)
	}

	tokRes, err := c.auth.GenerateAuthTokens(ctx, &authpb.GenerateAuthTokensRequest{
		Challenge:       msg,
		ClientPubkey:    c.kp.PublicKey().Bytes(),
		SignedChallenge: sig[:],
	})
	if err != nil {
		return fmt.Errorf("jito: tokens: %w", err)
	}

	c.tok.set(tokRes.AccessToken.Value)
	c.refreshTok = tokRes.RefreshToken.Value
	go c.refreshLoop(ctx, tokRes.AccessToken.ExpiresAtUtc.AsTime())
	return nil
}

func (c *client) refreshLoop(ctx context.Context, expiry time.Time) {
	for {
		// refresh a couple minutes early so a burst of bundles never hits an expired token
		wait := time.Until(expiry) - 2*time.Minute
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		var res *authpb.RefreshAccessTokenResponse
		err := withRetry(ctx, 3, func() error {
			var rpcErr error
			res, rpcErr = c.auth.RefreshAccessToken(ctx, &authpb.RefreshAccessTokenRequest{
				RefreshToken: c.refreshTok,
			})
			return rpcErr
		})
		if err != nil {
			log.Printf("jito: refresh: %v, re-authenticating", err)
			if err := c.authenticate(ctx); err != nil {
				log.Printf("jito: re-auth: %v", err)
				time.Sleep(5 * time.Second)
			}
			return
		}

		c.tok.set(res.AccessToken.Value)
		expiry = res.AccessToken.ExpiresAtUtc.AsTime()
	}
}

func (c *client) tipAccount(ctx context.Context) (solana.PublicKey, error) {
	c.tipMu.RLock()
	if len(c.tipAccounts) > 0 {
		a := c.tipAccounts[rand.Intn(len(c.tipAccounts))]
		c.tipMu.RUnlock()
		return a, nil
	}
	c.tipMu.RUnlock()

	res, err := c.searcher.GetTipAccounts(ctx, &searcherpb.GetTipAccountsRequest{})
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("jito: tip accts: %w", err)
	}

	tips := make([]solana.PublicKey, 0, len(res.Accounts))
	for _, a := range res.Accounts {
		pk, err := solana.PublicKeyFromBase58(a)
		if err != nil {
			return solana.PublicKey{}, fmt.Errorf("jito: bad tip acct %s: %w", a, err)
		}
		tips = append(tips, pk)
	}

	c.tipMu.Lock()
	c.tipAccounts = tips
	c.tipMu.Unlock()

	return tips[rand.Intn(len(tips))], nil
}

func (c *client) buildTransferTx(ctx context.Context, to solana.PublicKey, lamports uint64) (*solana.Transaction, error) {
	bh, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return nil, fmt.Errorf("jito: blockhash: %w", err)
	}

	ix := system.NewTransferInstruction(lamports, c.kp.PublicKey(), to).Build()
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, bh.Value.Blockhash, solana.TransactionPayer(c.kp.PublicKey()))
	if err != nil {
		return nil, fmt.Errorf("jito: build tx: %w", err)
	}

	if _, err := tx.Sign(func(pk solana.PublicKey) *solana.PrivateKey {
		if pk.Equals(c.kp.PublicKey()) {
			return &c.kp
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("jito: sign tx: %w", err)
	}

	return tx, nil
}

func (c *client) buildTipTx(ctx context.Context, lamports uint64) (*solana.Transaction, error) {
	tip, err := c.tipAccount(ctx)
	if err != nil {
		return nil, err
	}
	return c.buildTransferTx(ctx, tip, lamports)
}

// submitBundle sends txs as one bundle and returns the server-assigned uuid,
// which shows up again in the results stream so it can be matched to a
// land/drop/reject outcome. The tip transfer is the caller's problem: build
// it with buildTipTx and put it in txs like any other transaction.
func (c *client) submitBundle(ctx context.Context, txs []*solana.Transaction) (string, error) {
	if len(txs) == 0 || len(txs) > bundleCap {
		return "", fmt.Errorf("jito: bundle: need 1-%d txs, got %d", bundleCap, len(txs))
	}

	pkts := make([]*packetpb.Packet, 0, len(txs))
	for _, tx := range txs {
		raw, err := tx.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("jito: marshal: %w", err)
		}
		pkts = append(pkts, &packetpb.Packet{
			Data: raw,
			Meta: &packetpb.Meta{Size: uint64(len(raw))},
		})
	}

	var res *searcherpb.SendBundleResponse
	err := withRetry(ctx, 3, func() error {
		var rpcErr error
		res, rpcErr = c.searcher.SendBundle(ctx, &searcherpb.SendBundleRequest{
			Bundle: &bundlepb.Bundle{Packets: pkts},
		})
		return rpcErr
	})
	if err != nil {
		return "", fmt.Errorf("jito: send: %w", err)
	}

	atomic.AddUint64(&c.stats.submitted, 1)
	return res.Uuid, nil
}

// trackResults keeps the results stream open and reconnects on drops,
// updating the running land rate until ctx is cancelled.
func (c *client) trackResults(ctx context.Context) {
	for ctx.Err() == nil {
		if err := c.streamResults(ctx); err != nil && ctx.Err() == nil {
			log.Printf("jito: results stream: %v, reconnecting", err)
			time.Sleep(time.Second)
		}
	}
}

func (c *client) streamResults(ctx context.Context) error {
	stream, err := c.searcher.SubscribeBundleResults(ctx, &searcherpb.SubscribeBundleResultsRequest{})
	if err != nil {
		return fmt.Errorf("jito: subscribe: %w", err)
	}

	for {
		res, err := stream.Recv()
		if err != nil {
			return err
		}

		switch res.Result.(type) {
		case *bundlepb.BundleResult_Finalized:
			atomic.AddUint64(&c.stats.landed, 1)
		case *bundlepb.BundleResult_Dropped:
			atomic.AddUint64(&c.stats.dropped, 1)
		case *bundlepb.BundleResult_Rejected:
			atomic.AddUint64(&c.stats.rejected, 1)
		}
	}
}

// withRetry retries transient grpc failures with a short linear backoff;
// the block engine blips under load and a retry is usually all it takes.
func withRetry(ctx context.Context, attempts int, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		st, ok := status.FromError(err)
		if !ok || (st.Code() != codes.Unavailable && st.Code() != codes.ResourceExhausted) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(i+1) * 250 * time.Millisecond):
		}
	}
	return err
}

// runDemo submits n bundles back-to-back, each a self-transfer standing in
// for whatever trade tx your strategy builds plus a tip transfer.
func runDemo(ctx context.Context, c *client, n int, tipLamports uint64) error {
	for i := 0; i < n; i++ {
		tradeTx, err := c.buildTransferTx(ctx, c.kp.PublicKey(), 1000+uint64(i))
		if err != nil {
			return fmt.Errorf("jito: demo tx: %w", err)
		}
		tipTx, err := c.buildTipTx(ctx, tipLamports)
		if err != nil {
			return fmt.Errorf("jito: tip tx: %w", err)
		}
		uuid, err := c.submitBundle(ctx, []*solana.Transaction{tradeTx, tipTx})
		if err != nil {
			return fmt.Errorf("jito: submit: %w", err)
		}
		log.Printf("submitted bundle %s", uuid)
	}
	return nil
}

func main() {
	keypairPath := flag.String("keypair", "", "path to solana-keygen json keypair")
	blockEngineAddr := flag.String("block-engine", "", "jito block engine grpc address")
	rpcURL := flag.String("rpc", "", "solana rpc url")
	tipLamports := flag.Uint64("tip-lamports", 10000, "lamports to tip per bundle")
	bundleCount := flag.Int("bundles", 1, "number of demo bundles to submit")
	flag.Parse()

	if *keypairPath == "" || *blockEngineAddr == "" || *rpcURL == "" {
		log.Fatal("jito: -keypair, -block-engine and -rpc are required")
	}

	kp, err := solana.PrivateKeyFromSolanaKeygenFile(*keypairPath)
	if err != nil {
		log.Fatalf("jito: keypair: %v", err)
	}

	ctx := context.Background()
	c, err := newClient(ctx, *blockEngineAddr, *rpcURL, kp)
	if err != nil {
		log.Fatalf("jito: new client: %v", err)
	}
	defer c.conn.Close()

	go c.trackResults(ctx)

	if err := runDemo(ctx, c, *bundleCount, *tipLamports); err != nil {
		log.Fatalf("%v", err)
	}

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	const maxTicks = 20 // 10 minutes of polling tops, then just stop
	for i := 0; i < maxTicks; i++ {
		<-t.C
		sub, landed, dropped, rejected := c.stats.snapshot()
		if sub == 0 {
			continue
		}
		log.Printf("land rate: %.1f%% (landed %d, dropped %d, rejected %d, submitted %d)",
			100*float64(landed)/float64(sub), landed, dropped, rejected, sub)
		if landed+dropped+rejected >= sub {
			return
		}
	}
}
