package com.wakestation.android.ui.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.wakestation.android.R
import com.wakestation.android.data.model.PC
import com.wakestation.android.databinding.ItemPcBinding

class PCAdapter(
    private val onWakeClick: (PC) -> Unit,
    private val onShutdownClick: (PC) -> Unit,
    private val onDeleteClick: (PC) -> Unit
) : ListAdapter<PC, PCAdapter.PCViewHolder>(PCDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PCViewHolder {
        val binding = ItemPcBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return PCViewHolder(binding)
    }

    override fun onBindViewHolder(holder: PCViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class PCViewHolder(private val binding: ItemPcBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(pc: PC) {
            binding.apply {
                tvHostname.text = pc.hostname
                tvMac.text = pc.mac
                tvIp.text = if (pc.ip.isNotEmpty()) pc.ip else "No IP"

                // Status indicator
                val statusColor = when (pc.status) {
                    "online" -> ContextCompat.getColor(root.context, R.color.status_online)
                    "offline" -> ContextCompat.getColor(root.context, R.color.status_offline)
                    else -> ContextCompat.getColor(root.context, R.color.status_unknown)
                }
                viewStatus.setBackgroundColor(statusColor)

                tvStatus.text = pc.status.replaceFirstChar { it.uppercase() }

                // Daemon availability
                tvDaemonStatus.text = if (pc.daemon_available) {
                    "Shutdown Available"
                } else {
                    "No Shutdown Daemon"
                }

                // IP source (for debugging)
                if (pc.ip_source != null) {
                    tvIpSource.text = "IP from: ${pc.ip_source}"
                    tvIpSource.visibility = android.view.View.VISIBLE
                } else {
                    tvIpSource.visibility = android.view.View.GONE
                }

                // Button states
                btnWake.isEnabled = true // WOL can always be attempted
                btnShutdown.isEnabled = pc.canShutdown
                btnDelete.isEnabled = true

                // Click listeners
                btnWake.setOnClickListener { onWakeClick(pc) }
                btnShutdown.setOnClickListener { onShutdownClick(pc) }
                btnDelete.setOnClickListener { onDeleteClick(pc) }
            }
        }
    }

    private class PCDiffCallback : DiffUtil.ItemCallback<PC>() {
        override fun areItemsTheSame(oldItem: PC, newItem: PC): Boolean {
            return oldItem.mac == newItem.mac
        }

        override fun areContentsTheSame(oldItem: PC, newItem: PC): Boolean {
            return oldItem == newItem
        }
    }
}