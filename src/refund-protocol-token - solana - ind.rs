//! Integrated Refund Protocol with Native Token

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, MintTo, Transfer, Burn};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

const MAX_LOCKUP_SECONDS: i64 = 60 * 60 * 24 * 180; // 180 days
const PROTOCOL_FEE_BASIS_POINTS: u64 = 50; // 0.5% protocol fee
const STAKING_REWARD_RATE: u64 = 500; // 5% APY in basis points
const SECONDS_PER_YEAR: i64 = 365 * 24 * 60 * 60;
const TOKEN_REWARD_MULTIPLIER: u64 = 1_000_000; // 1 token per USDC (assuming 6 decimals)

#[program]
pub mod refund_protocol_with_token {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        arbiter: Pubkey,
    ) -> Result<()> {
        let protocol_state = &mut ctx.accounts.protocol_state;
        protocol_state.arbiter = arbiter;
        protocol_state.usdc_mint = ctx.accounts.usdc_mint.key();
        protocol_state.protocol_token_mint = ctx.accounts.protocol_token_mint.key();
        protocol_state.nonce = 0;
        protocol_state.total_protocol_tokens = 1_000_000_000 * 10u64.pow(9); // 1B tokens
        protocol_state.protocol_fee_basis_points = PROTOCOL_FEE_BASIS_POINTS;
        protocol_state.total_fees_collected = 0;
        protocol_state.total_tokens_staked = 0;
        protocol_state.bump = *ctx.bumps.get("protocol_state").unwrap();
        
        // Mint initial supply to protocol token vault
        let seeds = &[
            b"protocol_state".as_ref(),
            &[protocol_state.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = MintTo {
            mint: ctx.accounts.protocol_token_mint.to_account_info(),
            to: ctx.accounts.protocol_token_vault.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::mint_to(cpi_ctx, protocol_state.total_protocol_tokens)?;

        Ok(())
    }

    pub fn pay(
        ctx: Context<Pay>,
        amount: u64,
        refund_to: Pubkey,
    ) -> Result<()> {
        if refund_to == Pubkey::default() {
            return err!(ErrorCode::RefundToIsZeroAddress);
        }

        let protocol_state = &mut ctx.accounts.protocol_state;
        let recipient = ctx.accounts.recipient.key();
        
        // Calculate protocol fee
        let fee_amount = amount
            .checked_mul(protocol_state.protocol_fee_basis_points).unwrap()
            .checked_div(10000).unwrap();
        let net_amount = amount.checked_sub(fee_amount).unwrap();
        
        // Transfer USDC to protocol vault
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.payer_usdc_account.to_account_info(),
            to: ctx.accounts.protocol_usdc_vault.to_account_info(),
            authority: ctx.accounts.payer.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        // Update total fees collected
        protocol_state.total_fees_collected = protocol_state.total_fees_collected.checked_add(fee_amount).unwrap();
        
        // Create payment
        let payment = &mut ctx.accounts.payment;
        payment.to = recipient;
        payment.amount = net_amount; // Net amount after fee
        payment.fee_amount = fee_amount;
        payment.release_timestamp = Clock::get()?.unix_timestamp + 
            ctx.accounts.recipient_info.lockup_seconds as i64;
        payment.refund_to = refund_to;
        payment.withdrawn_amount = 0;
        payment.refunded = false;
        payment.payment_id = protocol_state.nonce;
        payment.bump = *ctx.bumps.get("payment").unwrap();
        
        // Update recipient balance
        let recipient_info = &mut ctx.accounts.recipient_info;
        recipient_info.balance = recipient_info.balance.checked_add(net_amount).unwrap();
        
        // Reward payer with protocol tokens (1 token per USDC paid)
        let token_reward = amount.checked_div(TOKEN_REWARD_MULTIPLIER).unwrap();
        if token_reward > 0 {
            self.mint_protocol_tokens_to_user(
                &ctx.accounts.protocol_state,
                &ctx.accounts.protocol_token_mint,
                &ctx.accounts.payer_protocol_token_account,
                &ctx.accounts.token_program,
                token_reward,
                protocol_state.bump,
            )?;
        }
        
        // Increment nonce
        protocol_state.nonce = protocol_state.nonce.checked_add(1).unwrap();
        
        emit!(PaymentCreated {
            payment_id: payment.payment_id,
            to: recipient,
            amount: net_amount,
            fee_amount,
            release_timestamp: payment.release_timestamp,
            refund_to,
            token_reward,
        });
        
        Ok(())
    }

    pub fn refund_by_recipient(ctx: Context<RefundByRecipient>) -> Result<()> {
        let payment = &ctx.accounts.payment;
        let payment_id = payment.payment_id;
        let payment_amount = payment.amount;
        let refund_to = payment.refund_to;
        
        if payment.refunded {
            return err!(ErrorCode::PaymentRefunded);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        
        if payment_amount > recipient_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(payment_amount).unwrap();
        
        // Mark payment as refunded
        let payment = &mut ctx.accounts.payment;
        payment.refunded = true;
        
        // Transfer USDC from protocol vault to refund_to
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_usdc_vault.to_account_info(),
            to: ctx.accounts.refund_to_usdc_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, payment_amount)?;
        
        emit!(Refund {
            payment_id,
            refund_to,
            amount: payment_amount,
        });
        
        Ok(())
    }

    pub fn refund_by_arbiter(ctx: Context<RefundByArbiter>) -> Result<()> {
        let payment = &ctx.accounts.payment;
        let payment_id = payment.payment_id;
        let payment_amount = payment.amount;
        let refund_to = payment.refund_to;
        
        if payment.refunded {
            return err!(ErrorCode::PaymentRefunded);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        
        // Try to use recipient balance first
        if payment_amount <= recipient_info.balance {
            recipient_info.balance = recipient_info.balance.checked_sub(payment_amount).unwrap();
        } else {
            // Use arbiter balance
            if payment_amount > arbiter_info.balance {
                return err!(ErrorCode::InsufficientFunds);
            }
            
            arbiter_info.balance = arbiter_info.balance.checked_sub(payment_amount).unwrap();
            
            // Increase recipient debt
            recipient_info.debt = recipient_info.debt.checked_add(payment_amount).unwrap();
        }
        
        // Mark payment as refunded
        let payment = &mut ctx.accounts.payment;
        payment.refunded = true;
        
        // Transfer USDC from protocol vault to refund_to
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_usdc_vault.to_account_info(),
            to: ctx.accounts.refund_to_usdc_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, payment_amount)?;
        
        emit!(Refund {
            payment_id,
            refund_to,
            amount: payment_amount,
        });
        
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, payment_ids: Vec<u64>) -> Result<()> {
        let recipient = ctx.accounts.recipient.key();
        let recipient_info = &mut ctx.accounts.recipient_info;
        
        // Settle debt first
        settle_debt_internal(recipient_info, ctx.accounts.arbiter_info.as_mut());
        
        let mut total_amount = 0;
        
        // Process each payment
        for i in 0..payment_ids.len() {
            let payment_id = payment_ids[i];
            let payment_account_info = &ctx.remaining_accounts[i];
            
            // Deserialize payment account
            let payment = Account::<Payment>::try_from(payment_account_info)?;
            
            if payment.to != recipient {
                return err!(ErrorCode::CallerNotAllowed);
            }
            
            let current_time = Clock::get()?.unix_timestamp;
            if current_time < payment.release_timestamp {
                return err!(ErrorCode::PaymentIsStillLocked);
            }
            
            if payment.refunded {
                return err!(ErrorCode::PaymentRefunded);
            }
            
            let withdrawal_amount = payment.amount.checked_sub(payment.withdrawn_amount).unwrap();
            total_amount = total_amount.checked_add(withdrawal_amount).unwrap();
            
            // Update payment's withdrawn amount
            let mut payment_mut = Account::<Payment>::try_from_unchecked(payment_account_info)?;
            payment_mut.withdrawn_amount = payment.amount;
            payment_mut.exit(&ctx.program_id)?;
        }
        
        if total_amount > recipient_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(total_amount).unwrap();
        
        // Transfer USDC from protocol vault to recipient
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_usdc_vault.to_account_info(),
            to: ctx.accounts.recipient_usdc_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, total_amount)?;
        
        emit!(Withdrawal {
            to: recipient,
            amount: total_amount,
        });
        
        Ok(())
    }

    pub fn early_withdraw_with_tokens(
        ctx: Context<EarlyWithdrawWithTokens>,
        payment_ids: Vec<u64>,
        token_burn_amount: u64,
    ) -> Result<()> {
        let recipient = ctx.accounts.recipient.key();
        let recipient_info = &mut ctx.accounts.recipient_info;
        
        // Burn protocol tokens to enable early withdrawal
        let cpi_accounts = Burn {
            mint: ctx.accounts.protocol_token_mint.to_account_info(),
            from: ctx.accounts.recipient_protocol_token_account.to_account_info(),
            authority: ctx.accounts.recipient.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::burn(cpi_ctx, token_burn_amount)?;
        
        let mut total_amount = 0;
        let early_withdrawal_bonus = token_burn_amount.checked_div(1000).unwrap(); // 0.1% bonus per token burned
        
        // Process each payment (can withdraw early)
        for i in 0..payment_ids.len() {
            let payment_account_info = &ctx.remaining_accounts[i];
            let payment = Account::<Payment>::try_from(payment_account_info)?;
            
            if payment.to != recipient {
                return err!(ErrorCode::CallerNotAllowed);
            }
            
            if payment.refunded {
                return err!(ErrorCode::PaymentRefunded);
            }
            
            let withdrawal_amount = payment.amount.checked_sub(payment.withdrawn_amount).unwrap();
            total_amount = total_amount.checked_add(withdrawal_amount).unwrap();
            
            // Update payment's withdrawn amount
            let mut payment_mut = Account::<Payment>::try_from_unchecked(payment_account_info)?;
            payment_mut.withdrawn_amount = payment.amount;
            payment_mut.exit(&ctx.program_id)?;
        }
        
        // Add early withdrawal bonus
        total_amount = total_amount.checked_add(early_withdrawal_bonus).unwrap();
        
        if total_amount > recipient_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(total_amount).unwrap();
        
        // Transfer USDC from protocol vault to recipient
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_usdc_vault.to_account_info(),
            to: ctx.accounts.recipient_usdc_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, total_amount)?;
        
        emit!(EarlyWithdrawal {
            to: recipient,
            amount: total_amount,
            tokens_burned: token_burn_amount,
            bonus_amount: early_withdrawal_bonus,
        });
        
        Ok(())
    }

    pub fn stake_protocol_tokens(
        ctx: Context<StakeProtocolTokens>,
        amount: u64,
    ) -> Result<()> {
        let protocol_state = &mut ctx.accounts.protocol_state;
        
        // Transfer tokens to staking vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_protocol_token_account.to_account_info(),
            to: ctx.accounts.protocol_token_staking_vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // Update stake info
        let stake_info = &mut ctx.accounts.stake_info;
        stake_info.staked_amount = stake_info.staked_amount.checked_add(amount).unwrap();
        stake_info.last_claim_timestamp = Clock::get()?.unix_timestamp;

        // Update protocol state
        protocol_state.total_tokens_staked = protocol_state.total_tokens_staked.checked_add(amount).unwrap();

        emit!(ProtocolTokensStaked {
            user: ctx.accounts.user.key(),
            amount,
        });

        Ok(())
    }

    pub fn unstake_protocol_tokens(
        ctx: Context<UnstakeProtocolTokens>,
        amount: u64,
    ) -> Result<()> {
        let stake_info = &mut ctx.accounts.stake_info;
        let protocol_state = &mut ctx.accounts.protocol_state;
        
        if amount > stake_info.staked_amount {
            return err!(ErrorCode::InsufficientStakedTokens);
        }

        // Claim any pending rewards first
        self.claim_staking_rewards_internal(
            stake_info,
            protocol_state,
            &ctx.accounts.protocol_usdc_vault,
            &ctx.accounts.user_usdc_account,
            &ctx.accounts.token_program,
        )?;

        // Transfer tokens back to user
        let seeds = &[
            b"protocol_state".as_ref(),
            &[protocol_state.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.protocol_token_staking_vault.to_account_info(),
            to: ctx.accounts.user_protocol_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)?;

        // Update stake info
        stake_info.staked_amount = stake_info.staked_amount.checked_sub(amount).unwrap();
        
        // Update protocol state
        protocol_state.total_tokens_staked = protocol_state.total_tokens_staked.checked_sub(amount).unwrap();

        emit!(ProtocolTokensUnstaked {
            user: ctx.accounts.user.key(),
            amount,
        });

        Ok(())
    }

    pub fn claim_staking_rewards(ctx: Context<ClaimStakingRewards>) -> Result<()> {
        let stake_info = &mut ctx.accounts.stake_info;
        let protocol_state = &ctx.accounts.protocol_state;
        
        self.claim_staking_rewards_internal(
            stake_info,
            protocol_state,
            &ctx.accounts.protocol_usdc_vault,
            &ctx.accounts.user_usdc_account,
            &ctx.accounts.token_program,
        )
    }

    pub fn set_lockup_seconds(
        ctx: Context<SetLockupSeconds>,
        recipient: Pubkey,
        recipient_lockup_seconds: i64,
    ) -> Result<()> {
        if recipient_lockup_seconds > MAX_LOCKUP_SECONDS {
            return err!(ErrorCode::LockupSecondsExceedsMax);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        recipient_info.lockup_seconds = recipient_lockup_seconds;
        
        Ok(())
    }

    pub fn update_refund_to(ctx: Context<UpdateRefundTo>, new_refund_to: Pubkey) -> Result<()> {
        if new_refund_to == Pubkey::default() {
            return err!(ErrorCode::RefundToIsZeroAddress);
        }
        
        let payment = &mut ctx.accounts.payment;
        let old_refund_to = payment.refund_to;
        payment.refund_to = new_refund_to;
        
        emit!(RefundToUpdated {
            payment_id: payment.payment_id,
            old_refund_to,
            new_refund_to,
        });
        
        Ok(())
    }

    pub fn deposit_arbiter_funds(ctx: Context<DepositArbiterFunds>, amount: u64) -> Result<()> {
        // Transfer USDC to protocol vault
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.arbiter_usdc_account.to_account_info(),
            to: ctx.accounts.protocol_usdc_vault.to_account_info(),
            authority: ctx.accounts.arbiter.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        // Update arbiter balance
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        arbiter_info.balance = arbiter_info.balance.checked_add(amount).unwrap();
        
        Ok(())
    }

    pub fn withdraw_arbiter_funds(ctx: Context<WithdrawArbiterFunds>, amount: u64) -> Result<()> {
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        
        if amount > arbiter_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update arbiter balance
        arbiter_info.balance = arbiter_info.balance.checked_sub(amount).unwrap();
        
        // Transfer USDC from protocol vault to arbiter
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_usdc_vault.to_account_info(),
            to: ctx.accounts.arbiter_usdc_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    pub fn settle_debt(ctx: Context<SettleDebt>) -> Result<()> {
        settle_debt_internal(
            ctx.accounts.recipient_info.as_mut(),
            ctx.accounts.arbiter_info.as_mut(),
        )
    }

    // Helper functions
    fn mint_protocol_tokens_to_user(
        &self,
        protocol_state: &Account<ProtocolState>,
        mint: &Account<Mint>,
        to_account: &Account<TokenAccount>,
        token_program: &Program<Token>,
        amount: u64,
        bump: u8,
    ) -> Result<()> {
        let seeds = &[
            b"protocol_state".as_ref(),
            &[bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = MintTo {
            mint: mint.to_account_info(),
            to: to_account.to_account_info(),
            authority: protocol_state.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new_with_signer(token_program.to_account_info(), cpi_accounts, signer);
        token::mint_to(cpi_ctx, amount)?;

        Ok(())
    }

    fn claim_staking_rewards_internal(
        &self,
        stake_info: &mut Account<StakeInfo>,
        protocol_state: &Account<ProtocolState>,
        protocol_usdc_vault: &Account<TokenAccount>,
        user_usdc_account: &Account<TokenAccount>,
        token_program: &Program<Token>,
    ) -> Result<()> {
        let current_time = Clock::get()?.unix_timestamp;
        let time_staked = current_time - stake_info.last_claim_timestamp;
        
        // Calculate USDC rewards from protocol fees (5% APY)
        let usdc_rewards = (stake_info.staked_amount as u128)
            .checked_mul(STAKING_REWARD_RATE as u128).unwrap()
            .checked_mul(time_staked as u128).unwrap()
            .checked_div(10000 * SECONDS_PER_YEAR as u128).unwrap() as u64;

        if usdc_rewards > 0 {
            // Transfer USDC rewards from vault
            let seeds = &[
                b"protocol_state".as_ref(),
                &[protocol_state.bump],
            ];
            let signer = &[&seeds[..]];

            let cpi_accounts = Transfer {
                from: protocol_usdc_vault.to_account_info(),
                to: user_usdc_account.to_account_info(),
                authority: protocol_state.to_account_info(),
            };
            
            let cpi_ctx = CpiContext::new_with_signer(token_program.to_account_info(), cpi_accounts, signer);
            token::transfer(cpi_ctx, usdc_rewards)?;

            emit!(StakingRewardsClaimed {
                user: stake_info.user,
                usdc_amount: usdc_rewards,
            });
        }

        stake_info.last_claim_timestamp = current_time;
        Ok(())
    }
}

// Helper function for settling debt
fn settle_debt_internal(recipient_info: &mut Account<RecipientInfo>, arbiter_info: &mut Account<ArbiterInfo>) -> Result<()> {
    let recipient_debt = recipient_info.debt;
    let recipient_balance = recipient_info.balance;
    
    let settle_amount = std::cmp::min(recipient_balance, recipient_debt);
    
    recipient_info.balance = recipient_info.balance.checked_sub(settle_amount).unwrap();
    arbiter_info.balance = arbiter_info.balance.checked_add(settle_amount).unwrap();
    recipient_info.debt = recipient_info.debt.checked_sub(settle_amount).unwrap();
    
    Ok(())
}

// State accounts
#[account]
pub struct ProtocolState {
    pub arbiter: Pubkey,
    pub usdc_mint: Pubkey,
    pub protocol_token_mint: Pubkey,
    pub nonce: u64,
    pub total_protocol_tokens: u64,
    pub protocol_fee_basis_points: u64,
    pub total_fees_collected: u64,
    pub total_tokens_staked: u64,
    pub bump: u8,
}

#[account]
pub struct Payment {
    pub to: Pubkey,
    pub amount: u64,
    pub fee_amount: u64,
    pub release_timestamp: i64,
    pub refund_to: Pubkey,
    pub withdrawn_amount: u64,
    pub refunded: bool,
    pub payment_id: u64,
    pub bump: u8,
}

#[account]
pub struct RecipientInfo {
    pub recipient: Pubkey,
    pub balance: u64,
    pub debt: u64,
    pub lockup_seconds: i64,
    pub bump: u8,
}

#[account]
pub struct ArbiterInfo {
    pub arbiter: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[account]
pub struct StakeInfo {
    pub user: Pubkey,
    pub staked_amount: u64,
    pub last_claim_timestamp: i64,
    pub bump: u8,
}

// Events
#[event]
pub struct PaymentCreated {
    #[index]
    pub payment_id: u64,
    #[index]
    pub to: Pubkey,
    pub amount: u64,
    pub fee_amount: u64,
    pub release_timestamp: i64,
    #[index]
    pub refund_to: Pubkey,
    pub token_reward: u64,
}

#[event]
pub struct Refund {
    #[index]
    pub payment_id: u64,
    #[index]
    pub refund_to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct RefundToUpdated {
    #[index]
    pub payment_id: u64,
    #[index]
    pub old_refund_to: Pubkey,
    #[index]
    pub new_refund_to: Pubkey,
}

#[event]
pub struct Withdrawal {
    #[index]
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct EarlyWithdrawal {
    #[index]
    pub to: Pubkey,
    pub amount: u64,
    pub tokens_burned: u64,
    pub bonus_amount: u64,
}

#[event]
pub struct ProtocolTokensStaked {
    #[index]
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct ProtocolTokensUnstaked {
    #[index]
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct StakingRewardsClaimed {
    #[index]
    pub user: Pubkey,
    pub usdc_amount: u64,
}

// Error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Caller not allowed")]
    CallerNotAllowed,
    #[msg("Payment is still locked")]
    PaymentIsStillLocked,
    #[msg("Payment does not belong to recipient")]
    PaymentDoesNotBelongToRecipient,
    #[msg("Refund to address cannot be zero address")]
    RefundToIsZeroAddress,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid withdrawal amount")]
    InvalidWithdrawalAmount,
    #[msg("Invalid fee amount")]
    InvalidFeeAmount,
    #[msg("Payment already refunded")]
    PaymentRefunded,
    #[msg("Lockup seconds exceeds maximum")]
    LockupSecondsExceedsMax,
    #[msg("Insufficient staked tokens")]
    InsufficientStakedTokens,
}

// Context structs for instructions
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    #[account(
        init,
        payer = initializer,
        space = 8 + std::mem::size_of::<ProtocolState>(),
        seeds = [b"protocol_state"],
        bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    pub usdc_mint: Account<'info, Mint>,
    #[account(
        init,
        payer = initializer,
        mint::decimals = 9,
        mint::authority = protocol_state,
        seeds = [b"protocol_token_mint"],
        bump
    )]
    pub protocol_token_mint: Account<'info, Mint>,
    #[account(
        init,
        payer = initializer,
        token::mint = protocol_token_mint,
        token::authority = protocol_state,
        seeds = [b"protocol_token_vault"],
        bump
    )]
    pub protocol_token_vault: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(amount: u64, refund_to: Pubkey)]
pub struct Pay<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    /// CHECK: This is the recipient's main account address.
    pub recipient: AccountInfo<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + std::mem::size_of::<RecipientInfo>(),
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<Payment>(),
        seeds = [b"payment", protocol_state.nonce.to_le_bytes().as_ref()],
        bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        constraint = payer_usdc_account.owner == payer.key(),
        constraint = payer_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub payer_usdc_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = payer_protocol_token_account.owner == payer.key(),
        constraint = payer_protocol_token_account.mint == protocol_state.protocol_token_mint
    )]
    pub payer_protocol_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        seeds = [b"protocol_token_mint"],
        bump
    )]
    pub protocol_token_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RefundByRecipient<'info> {
    #[account(
        mut,
        constraint = recipient.key() == payment.to @ ErrorCode::CallerNotAllowed
    )]
    pub recipient: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = refund_to_usdc_account.owner == payment.refund_to,
        constraint = refund_to_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub refund_to_usdc_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct RefundByArbiter<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter @ ErrorCode::CallerNotAllowed
    )]
    pub arbiter: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [b"recipient_info", payment.to.as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        init_if_needed,
        payer = arbiter,
        space = 8 + std::mem::size_of::<ArbiterInfo>(),
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = refund_to_usdc_account.owner == payment.refund_to,
        constraint = refund_to_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub refund_to_usdc_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"arbiter_info", protocol_state.arbiter.as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = recipient_usdc_account.owner == recipient.key(),
        constraint = recipient_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub recipient_usdc_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    // remaining_accounts will contain the Payment accounts for withdrawal
}

#[derive(Accounts)]
pub struct EarlyWithdrawWithTokens<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"protocol_token_mint"],
        bump,
    )]
    pub protocol_token_mint: Account<'info, Mint>,
    #[account(
        mut,
        constraint = recipient_protocol_token_account.owner == recipient.key(),
        constraint = recipient_protocol_token_account.mint == protocol_state.protocol_token_mint
    )]
    pub recipient_protocol_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = recipient_usdc_account.owner == recipient.key(),
        constraint = recipient_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub recipient_usdc_account: Account<'info, TokenAccount>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    pub token_program: Program<'info, Token>,
    // remaining_accounts will contain the Payment accounts for withdrawal
}

#[derive(Accounts)]
pub struct StakeProtocolTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + std::mem::size_of::<StakeInfo>(),
        seeds = [b"stake_info", user.key().as_ref()],
        bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        constraint = user_protocol_token_account.owner == user.key(),
        constraint = user_protocol_token_account.mint == protocol_state.protocol_token_mint
    )]
    pub user_protocol_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.protocol_token_mint,
        token::authority = protocol_state,
    )]
    pub protocol_token_staking_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnstakeProtocolTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"stake_info", user.key().as_ref()],
        bump = stake_info.bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        constraint = user_protocol_token_account.owner == user.key(),
        constraint = user_protocol_token_account.mint == protocol_state.protocol_token_mint
    )]
    pub user_protocol_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.protocol_token_mint,
        token::authority = protocol_state,
    )]
    pub protocol_token_staking_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = user_usdc_account.owner == user.key(),
        constraint = user_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub user_usdc_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimStakingRewards<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"stake_info", user.key().as_ref()],
        bump = stake_info.bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = user_usdc_account.owner == user.key(),
        constraint = user_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub user_usdc_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(recipient: Pubkey)]
pub struct SetLockupSeconds<'info> {
    #[account(constraint = arbiter.key() == protocol_state.arbiter @ ErrorCode::CallerNotAllowed)]
    pub arbiter: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
}

#[derive(Accounts)]
pub struct UpdateRefundTo<'info> {
    #[account(
        mut,
        constraint = refund_to.key() == payment.refund_to @ ErrorCode::CallerNotAllowed
    )]
    pub refund_to: Signer<'info>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
}

#[derive(Accounts)]
pub struct DepositArbiterFunds<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter @ ErrorCode::CallerNotAllowed
    )]
    pub arbiter: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = arbiter_usdc_account.owner == arbiter.key(),
        constraint = arbiter_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub arbiter_usdc_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawArbiterFunds<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter @ ErrorCode::CallerNotAllowed
    )]
    pub arbiter: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = arbiter_usdc_account.owner == arbiter.key(),
        constraint = arbiter_usdc_account.mint == protocol_state.usdc_mint
    )]
    pub arbiter_usdc_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = protocol_state.usdc_mint,
        token::authority = protocol_state,
    )]
    pub protocol_usdc_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SettleDebt<'info> {
    /// CHECK: Can be any signer, typically the recipient or a third party settling the debt.
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient_info.recipient.as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"arbiter_info", protocol_state.arbiter.as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
}