/**
 * 
 */
package com.emc.settlement.model.backend.pojo.fileupload;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * @author DWTN1561
 *
 */
public class VestingContract  implements Serializable{

	
	public boolean checkPriceInDatabase=false;
	public String contractType;
	public String ebt_event_id;
	public String eveId;
	public String externalId;
	public boolean isFirstVcForSd=false;
	public String message;
	public String name;
	public Integer period;
	public Double price;
	public Double quantity;
	public String sacPurchaseId;
	public String sacSoldId;
	public String settlementAccount;
	public String settlementDate;
	public String standingVersion;
	public int validation_type;
	public List<Double> vcExistingContractPrice = new ArrayList<Double>();
	public List<String> vcExistingSacForSd = new ArrayList<String>();;
	public int vcTotalPeriodsForSacSd;
	
	protected static final Logger logger = Logger.getLogger(VestingContract.class);
	
	public boolean isCheckPriceInDatabase() {
		return checkPriceInDatabase;
	}
	public void setCheckPriceInDatabase(boolean checkPriceInDatabase) {
		this.checkPriceInDatabase = checkPriceInDatabase;
	}
	public String getContractType() {
		return contractType;
	}
	public void setContractType(String contractType) {
		this.contractType = contractType;
	}
	public String getEbt_event_id() {
		return ebt_event_id;
	}
	public void setEbt_event_id(String ebt_event_id) {
		this.ebt_event_id = ebt_event_id;
	}
	public String getEveId() {
		return eveId;
	}
	public void setEveId(String eveId) {
		this.eveId = eveId;
	}
	public String getExternalId() {
		return externalId;
	}
	public void setExternalId(String externalId) {
		this.externalId = externalId;
	}
	public boolean isFirstVcForSd() {
		return isFirstVcForSd;
	}
	public void setFirstVcForSd(boolean isFirstVcForSd) {
		this.isFirstVcForSd = isFirstVcForSd;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getPeriod() {
		return period;
	}
	public void setPeriod(int period) {
		this.period = period;
	}
	public Double getPrice() {
		return price;
	}
	public void setPrice(Double price) {
		this.price = price;
	}
	public Double getQuantity() {
		return quantity;
	}
	public void setQuantity(Double quantity) {
		this.quantity = quantity;
	}
	public String getSacPurchaseId() {
		return sacPurchaseId;
	}
	public void setSacPurchaseId(String sacPurchaseId) {
		this.sacPurchaseId = sacPurchaseId;
	}
	public String getSacSoldId() {
		return sacSoldId;
	}
	public void setSacSoldId(String sacSoldId) {
		this.sacSoldId = sacSoldId;
	}
	public String getSettlementAccount() {
		return settlementAccount;
	}
	public void setSettlementAccount(String settlementAccount) {
		this.settlementAccount = settlementAccount;
	}
	public String getSettlementDate() {
		return settlementDate;
	}
	public void setSettlementDate(String settlementDate) {
		this.settlementDate = settlementDate;
	}
	public String getStandingVersion() {
		return standingVersion;
	}
	public void setStandingVersion(String standingVersion) {
		this.standingVersion = standingVersion;
	}
	public int getValidation_type() {
		return validation_type;
	}
	public void setValidation_type(int validation_type) {
		this.validation_type = validation_type;
	}
	public List<Double> getVcExistingContractPrice() {
		return vcExistingContractPrice;
	}
	public void setVcExistingContractPrice(List<Double> vcExistingContractPrice) {
		this.vcExistingContractPrice = vcExistingContractPrice;
	}
	public List<String> getVcExistingSacForSd() {
		return vcExistingSacForSd;
	}
	public void setVcExistingSacForSd(List<String> vcExistingSacForSd) {
		this.vcExistingSacForSd = vcExistingSacForSd;
	}
	public int getVcTotalPeriodsForSacSd() {
		return vcTotalPeriodsForSacSd;
	}
	public void setVcTotalPeriodsForSacSd(int vcTotalPeriodsForSacSd) {
		this.vcTotalPeriodsForSacSd = vcTotalPeriodsForSacSd;
	}

	
}
